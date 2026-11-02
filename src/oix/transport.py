"""Bounded mutual-TLS transport for encrypted OIX envelopes.

The server binds to loopback by default. Public interfaces require an explicit
opt-in. The transport carries encrypted wrappers and returns signed durable
receipts; inner OIX signatures, prekeys, inbox policy, and replay checks remain
the authoritative application-level trust controls.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import ssl
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json
from .identity import fingerprint
from .inbox import SQLiteInbox
from .prekeys import MAX_PREKEY_ENVELOPE_BYTES, SQLitePreKeyStore
from .receipts import message_digest, verify_delivery_receipt

MAX_FRAME_BYTES = MAX_PREKEY_ENVELOPE_BYTES
MAX_STREAM_MESSAGES = 100
FRAME_HEADER_BYTES = 4
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2
logger = logging.getLogger(__name__)


class TransportError(RuntimeError):
    """A transport frame or authenticated peer exchange failed."""


_AGENT_ID_PATTERN = re.compile(r"^ed25519:[0-9a-f]{64}$")
_AGENT_URI_PREFIX = "urn:oix:agent:"


def agent_identity_uri(agent_id: str) -> str:
    """Return the X.509 URI SAN required to bind a TLS certificate to an OIX agent."""
    if not isinstance(agent_id, str) or not _AGENT_ID_PATTERN.fullmatch(agent_id):
        raise ValueError("agent_id must be a canonical OIX Ed25519 fingerprint")
    return _AGENT_URI_PREFIX + agent_id


def _certificate_agent_id(ssl_object: Any) -> str:
    """Extract exactly one OIX agent identity from a verified TLS peer certificate."""
    if ssl_object is None:
        raise TransportError("TLS peer certificate is unavailable")
    certificate_der = ssl_object.getpeercert(binary_form=True)
    if not certificate_der:
        raise TransportError("TLS peer certificate is unavailable")
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise TransportError("TLS peer certificate has no valid subject alternative name") from exc
    identities = [
        value.removeprefix(_AGENT_URI_PREFIX)
        for value in san.get_values_for_type(x509.UniformResourceIdentifier)
        if value.startswith(_AGENT_URI_PREFIX)
    ]
    if len(identities) != 1 or not _AGENT_ID_PATTERN.fullmatch(identities[0]):
        raise TransportError("TLS peer certificate must contain exactly one canonical OIX agent URI")
    return identities[0]


def encode_frame(value: dict[str, Any]) -> bytes:
    """Encode one canonical JSON object with a four-byte network-order length."""
    if not isinstance(value, dict):
        raise TransportError("transport frame must be a JSON object")
    try:
        payload = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise TransportError("transport frame is outside the OIX JSON data model") from exc
    if not 1 <= len(payload) <= MAX_FRAME_BYTES:
        raise TransportError("transport frame size is outside the permitted range")
    return len(payload).to_bytes(FRAME_HEADER_BYTES, "big") + payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransportError("transport frame contains duplicate JSON keys")
        result[key] = value
    return result


async def _decode_frame(
    reader: asyncio.StreamReader,
    prefix: bytes,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    length = int.from_bytes(prefix, "big")
    if not 1 <= length <= MAX_FRAME_BYTES:
        raise TransportError("transport frame length is outside the permitted range")
    try:
        payload = await asyncio.wait_for(reader.readexactly(length), timeout_seconds)
        value = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or canonical_json(value) != payload:
            raise TransportError("transport frame is not a canonical JSON object")
        return value
    except TimeoutError as exc:
        raise TransportError("transport frame read timed out") from exc
    except asyncio.IncompleteReadError as exc:
        raise TransportError("transport frame was truncated") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, TransportError):
            raise
        raise TransportError("transport frame is malformed") from exc


async def read_frame(
    reader: asyncio.StreamReader,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Read exactly one bounded canonical JSON frame."""
    try:
        prefix = await asyncio.wait_for(
            reader.readexactly(FRAME_HEADER_BYTES), timeout_seconds
        )
    except TimeoutError as exc:
        raise TransportError("transport frame read timed out") from exc
    except asyncio.IncompleteReadError as exc:
        raise TransportError("transport frame was truncated") from exc
    return await _decode_frame(reader, prefix, timeout_seconds=timeout_seconds)


async def _read_stream_frame(
    reader: asyncio.StreamReader,
    *,
    idle_timeout_seconds: float,
    frame_timeout_seconds: float,
) -> dict[str, Any] | None:
    """Read a frame, returning None only for clean idle timeout or clean EOF."""
    try:
        prefix = await asyncio.wait_for(
            reader.readexactly(FRAME_HEADER_BYTES), idle_timeout_seconds
        )
    except TimeoutError:
        return None
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise TransportError("transport frame header was truncated") from exc
    return await _decode_frame(
        reader, prefix, timeout_seconds=frame_timeout_seconds
    )


async def write_frame(
    writer: asyncio.StreamWriter,
    value: dict[str, Any],
    *,
    timeout_seconds: float = 10.0,
) -> None:
    frame = encode_frame(value)
    writer.write(frame)
    try:
        await asyncio.wait_for(writer.drain(), timeout_seconds)
    except TimeoutError as exc:
        raise TransportError("transport frame write timed out") from exc


def _require_server_tls(context: ssl.SSLContext) -> None:
    if not isinstance(context, ssl.SSLContext):
        raise TypeError("ssl_context must be an SSLContext")
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("server TLS context must require a trusted client certificate")
    if context.minimum_version < MIN_TLS_VERSION:
        raise ValueError("TLS 1.2 or newer is required")


def _require_client_tls(context: ssl.SSLContext) -> None:
    if not isinstance(context, ssl.SSLContext):
        raise TypeError("ssl_context must be an SSLContext")
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError("client TLS context must verify the server certificate and hostname")
    if context.minimum_version < MIN_TLS_VERSION:
        raise ValueError("TLS 1.2 or newer is required")


class OIXMutualTLSServer:
    """Persistent bounded OIX session receiver with local inbox and backpressure."""

    def __init__(
        self,
        inbox: SQLiteInbox,
        prekey_store: SQLitePreKeyStore,
        signing_private_key: Ed25519PrivateKey,
        *,
        timeout_seconds: float = 10.0,
        idle_timeout_seconds: float = 30.0,
        max_concurrent: int = 32,
        max_messages_per_connection: int = MAX_STREAM_MESSAGES,
    ) -> None:
        if not isinstance(signing_private_key, Ed25519PrivateKey):
            raise TypeError("signing_private_key must be an Ed25519PrivateKey")
        if fingerprint(signing_private_key.public_key().public_bytes_raw()) != inbox.local_agent_id:
            raise ValueError("signing key does not belong to the inbox identity")
        if (
            Path(inbox.database).resolve()
            != Path(prekey_store.database).resolve()
        ):
            raise ValueError("inbox and prekey store must share one SQLite database")
        if not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0.1 and 120")
        if not 0.1 <= idle_timeout_seconds <= 300:
            raise ValueError("idle_timeout_seconds must be between 0.1 and 300")
        if not 1 <= max_concurrent <= 1024:
            raise ValueError("max_concurrent must be between 1 and 1024")
        if not 1 <= max_messages_per_connection <= MAX_STREAM_MESSAGES:
            raise ValueError(f"max_messages_per_connection must be between 1 and {MAX_STREAM_MESSAGES}")
        self.inbox = inbox
        self.prekey_store = prekey_store
        self.signing_private_key = signing_private_key
        self.timeout_seconds = timeout_seconds
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_messages_per_connection = max_messages_per_connection
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._server: asyncio.AbstractServer | None = None

    async def start(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        ssl_context: ssl.SSLContext,
        allow_public_bind: bool = False,
    ) -> tuple[str, int]:
        if self._server is not None:
            raise TransportError("server is already running")
        _require_server_tls(ssl_context)
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("host must be an explicit IP address") from exc
        if not address.is_loopback and not allow_public_bind:
            raise ValueError("non-loopback binding requires allow_public_bind=True")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=ssl_context,
            limit=MAX_FRAME_BYTES + FRAME_HEADER_BYTES,
        )
        socket = self._server.sockets[0]
        bound_host, bound_port = socket.getsockname()[:2]
        return str(bound_host), int(bound_port)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        acquired = False
        try:
            await asyncio.wait_for(
                self._semaphore.acquire(), timeout=self.timeout_seconds
            )
            acquired = True
            tls_peer = writer.get_extra_info("ssl_object")
            certificate_agent_id = _certificate_agent_id(tls_peer)
            for _ in range(self.max_messages_per_connection):
                secure = await _read_stream_frame(
                    reader,
                    idle_timeout_seconds=self.idle_timeout_seconds,
                    frame_timeout_seconds=self.timeout_seconds,
                )
                if secure is None:
                    break
                header = secure.get("header")
                if not isinstance(header, dict) or not isinstance(header.get("sender"), str):
                    raise TransportError("encrypted envelope has no sender identity")
                sender_id = header["sender"]
                if certificate_agent_id != sender_id:
                    raise TransportError(
                        "TLS client certificate identity does not match OIX sender"
                    )
                sender_public_key = self.inbox.trusted_peer_public_key(sender_id)
                _, receipt = await asyncio.to_thread(
                    self.prekey_store.consume_and_acknowledge,
                    secure,
                    self.inbox,
                    self.signing_private_key.public_key().public_bytes_raw(),
                    sender_public_key,
                    self.inbox.local_agent_id,
                    self.signing_private_key,
                )
                await write_frame(writer, receipt, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            # Log only the exception class; never disclose parser or cryptographic details.
            logger.warning("OIX transport session rejected (%s)", type(exc).__name__)
        finally:
            if acquired:
                self._semaphore.release()
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), self.timeout_seconds)

    async def serve_forever(self) -> None:
        if self._server is None:
            raise TransportError("server has not been started")
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None


async def send_encrypted_stream(
    secure_envelopes: list[dict[str, Any]],
    *,
    expected_message_ids: list[str],
    host: str,
    port: int,
    server_hostname: str,
    ssl_context: ssl.SSLContext,
    local_agent_id: str,
    expected_peer_agent_id: str,
    expected_peer_signing_public_key: bytes,
    timeout_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    """Send multiple persisted encrypted envelopes over one authenticated TLS session.

    Each envelope is acknowledged before the next is sent, providing natural
    backpressure. The caller owns retry policy and must reuse each exact
    persisted encrypted wrapper after a timeout or connection loss.
    """
    _require_client_tls(ssl_context)
    if not 0.1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be between 0.1 and 120")
    if (
        not isinstance(secure_envelopes, list)
        or not 1 <= len(secure_envelopes) <= MAX_STREAM_MESSAGES
        or not isinstance(expected_message_ids, list)
        or len(expected_message_ids) != len(secure_envelopes)
    ):
        raise ValueError(
            f"secure_envelopes and expected_message_ids must be lists of 1 to {MAX_STREAM_MESSAGES} matching items"
        )
    for secure, message_id in zip(secure_envelopes, expected_message_ids, strict=True):
        header = secure.get("header", {}) if isinstance(secure, dict) else {}
        if (
            not isinstance(header, dict)
            or header.get("sender") != local_agent_id
            or header.get("recipient") != expected_peer_agent_id
            or not isinstance(message_id, str)
            or not message_id
        ):
            raise TransportError("encrypted envelope route or expected message ID is invalid")
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
                limit=MAX_FRAME_BYTES + FRAME_HEADER_BYTES,
            ),
            timeout_seconds,
        )
        tls_peer = writer.get_extra_info("ssl_object")
        if _certificate_agent_id(tls_peer) != expected_peer_agent_id:
            raise TransportError(
                "TLS server certificate identity does not match expected OIX peer"
            )
        receipts: list[dict[str, Any]] = []
        for secure, message_id in zip(secure_envelopes, expected_message_ids, strict=True):
            await write_frame(writer, secure, timeout_seconds=timeout_seconds)
            receipt = await read_frame(reader, timeout_seconds=timeout_seconds)
            if not verify_delivery_receipt(
                receipt,
                expected_peer_signing_public_key,
                expected_recipient_agent_id=expected_peer_agent_id,
                expected_sender_agent_id=local_agent_id,
                expected_message_id=message_id,
                expected_content_digest=message_digest(secure),
            ):
                raise TransportError(
                    "peer receipt signature or encrypted-message binding is invalid"
                )
            receipts.append(receipt)
        return receipts
    except TimeoutError as exc:
        raise TransportError("mutual-TLS exchange timed out") from exc
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout_seconds)


async def send_encrypted_envelope(
    secure_envelope: dict[str, Any],
    *,
    host: str,
    port: int,
    server_hostname: str,
    ssl_context: ssl.SSLContext,
    local_agent_id: str,
    expected_peer_agent_id: str,
    expected_message_id: str,
    expected_peer_signing_public_key: bytes,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Send one persisted encrypted envelope and verify its signed durable receipt."""
    receipts = await send_encrypted_stream(
        [secure_envelope],
        expected_message_ids=[expected_message_id],
        host=host,
        port=port,
        server_hostname=server_hostname,
        ssl_context=ssl_context,
        local_agent_id=local_agent_id,
        expected_peer_agent_id=expected_peer_agent_id,
        expected_peer_signing_public_key=expected_peer_signing_public_key,
        timeout_seconds=timeout_seconds,
    )
    return receipts[0]


# Discovery exchange transport is separate from the encrypted task-message inbox.
# A relay may carry signed public discovery records without being trusted to execute work.
from .discovery import SQLiteDiscoveryStore
from .discovery_exchange import (
    MAX_EXCHANGE_BYTES,
    ExchangeError,
    ingest_exchange_batch,
    inspect_exchange_batch,
)

MAX_DISCOVERY_FRAME_BYTES = MAX_EXCHANGE_BYTES


class OIXDiscoveryExchangeServer:
    """Receive bounded signed-discovery batches from explicitly approved TLS relays.

    The relay identity is authenticated by mutual TLS and an OIX URI SAN. The
    relay must also appear in the local operator-approved relay list. Records
    inside the batch are independently verified and remain discovered_untrusted.
    """

    def __init__(
        self,
        store: SQLiteDiscoveryStore,
        approved_relay_agent_ids: set[str] | list[str] | tuple[str, ...],
        *,
        timeout_seconds: float = 10.0,
        max_concurrent: int = 16,
    ) -> None:
        if not isinstance(store, SQLiteDiscoveryStore):
            raise TypeError("store must be a SQLiteDiscoveryStore")
        if not isinstance(approved_relay_agent_ids, (set, list, tuple)):
            raise TypeError("approved_relay_agent_ids must be an explicit collection")
        peers = list(approved_relay_agent_ids)
        if not peers or any(
            not isinstance(peer, str) or not _AGENT_ID_PATTERN.fullmatch(peer)
            for peer in peers
        ):
            raise ValueError("at least one canonical approved relay agent ID is required")
        if len(peers) != len(set(peers)) or len(peers) > 256:
            raise ValueError("approved relay list must be unique and contain at most 256 peers")
        if not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0.1 and 120")
        if not 1 <= max_concurrent <= 128:
            raise ValueError("max_concurrent must be between 1 and 128")
        self.store = store
        self.approved_relay_agent_ids = frozenset(peers)
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._server: asyncio.AbstractServer | None = None

    async def start(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        ssl_context: ssl.SSLContext,
        allow_public_bind: bool = False,
    ) -> tuple[str, int]:
        if self._server is not None:
            raise TransportError("discovery exchange server is already running")
        _require_server_tls(ssl_context)
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("host must be an explicit IP address") from exc
        if not address.is_loopback and not allow_public_bind:
            raise ValueError("non-loopback binding requires allow_public_bind=True")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=ssl_context,
            limit=MAX_DISCOVERY_FRAME_BYTES + FRAME_HEADER_BYTES,
        )
        bound = self._server.sockets[0].getsockname()
        return str(bound[0]), int(bound[1])

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        acquired = False
        try:
            await asyncio.wait_for(
                self._semaphore.acquire(), timeout=self.timeout_seconds
            )
            acquired = True
            peer = _certificate_agent_id(writer.get_extra_info("ssl_object"))
            if peer not in self.approved_relay_agent_ids:
                raise TransportError("TLS relay is not in the operator-approved relay list")
            batch = await read_frame(reader, timeout_seconds=self.timeout_seconds)
            result = await asyncio.to_thread(
                ingest_exchange_batch,
                batch,
                self.store,
                now=__import__("time").time_ns() // 1_000_000_000,
            )
            acknowledgement = {
                "protocol": "OIX-DISCOVERY-ACK",
                "protocol_version": "0.1",
                "batch_id": result["batch_id"],
                "batch_sha256": result["batch_sha256"],
                "received": result["received"],
                "accepted_count": result["accepted_count"],
                "rejected_count": result["rejected_count"],
                "trust_state": "discovered_untrusted",
            }
            await write_frame(
                writer, acknowledgement, timeout_seconds=self.timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "OIX discovery transport session rejected (%s)", type(exc).__name__
            )
        finally:
            if acquired:
                self._semaphore.release()
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), self.timeout_seconds)

    async def serve_forever(self) -> None:
        if self._server is None:
            raise TransportError("discovery exchange server has not been started")
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None


async def send_discovery_exchange(
    batch: dict[str, Any],
    *,
    host: str,
    port: int,
    server_hostname: str,
    ssl_context: ssl.SSLContext,
    expected_peer_agent_id: str,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Send one bounded discovery batch to an explicitly selected, TLS-pinned OIX peer."""
    _require_client_tls(ssl_context)
    if not isinstance(expected_peer_agent_id, str) or not _AGENT_ID_PATTERN.fullmatch(
        expected_peer_agent_id
    ):
        raise ValueError("expected_peer_agent_id must be a canonical OIX agent ID")
    if not 0.1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be between 0.1 and 120")
    try:
        records, digest = inspect_exchange_batch(
            batch, now=__import__("time").time_ns() // 1_000_000_000
        )
    except (ExchangeError, TypeError, ValueError) as exc:
        raise TransportError("outbound discovery batch failed validation") from exc
    payload_size = len(canonical_json(batch))
    if not 1 <= payload_size <= MAX_DISCOVERY_FRAME_BYTES:
        raise TransportError("discovery frame exceeds the permitted byte limit")

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
                limit=MAX_DISCOVERY_FRAME_BYTES + FRAME_HEADER_BYTES,
            ),
            timeout_seconds,
        )
        peer = _certificate_agent_id(writer.get_extra_info("ssl_object"))
        if peer != expected_peer_agent_id:
            raise TransportError("TLS server certificate identity does not match expected OIX peer")
        await write_frame(writer, batch, timeout_seconds=timeout_seconds)
        acknowledgement = await read_frame(reader, timeout_seconds=timeout_seconds)
        required = {
            "protocol", "protocol_version", "batch_id", "batch_sha256",
            "received", "accepted_count", "rejected_count", "trust_state",
        }
        if (
            not isinstance(acknowledgement, dict)
            or set(acknowledgement) != required
            or acknowledgement.get("protocol") != "OIX-DISCOVERY-ACK"
            or acknowledgement.get("protocol_version") != "0.1"
            or acknowledgement.get("batch_id") != batch["exchange"]["batch_id"]
            or acknowledgement.get("batch_sha256") != digest
            or acknowledgement.get("received") != len(records)
            or acknowledgement.get("trust_state") != "discovered_untrusted"
            or not isinstance(acknowledgement.get("accepted_count"), int)
            or isinstance(acknowledgement.get("accepted_count"), bool)
            or not isinstance(acknowledgement.get("rejected_count"), int)
            or isinstance(acknowledgement.get("rejected_count"), bool)
            or acknowledgement["accepted_count"] + acknowledgement["rejected_count"]
            != len(records)
        ):
            raise TransportError("discovery acknowledgement does not match the sent batch")
        return {"tls_peer_agent_id": peer, **acknowledgement}
    except TimeoutError as exc:
        raise TransportError("discovery exchange timed out") from exc
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout_seconds)
