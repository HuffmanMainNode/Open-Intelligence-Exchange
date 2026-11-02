from __future__ import annotations

import asyncio
import ipaddress
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from oix.envelope import create_message
from oix.identity import generate_identity, load_private_key
from oix.inbox import SQLiteInbox
from oix.policy import CapabilityPolicy
from oix.prekeys import SQLitePreKeyStore, create_prekey_bundle, encrypt_prekey_envelope
from oix.transport import (
    MAX_FRAME_BYTES,
    OIXMutualTLSServer,
    TransportError,
    encode_frame,
    read_frame,
    send_encrypted_envelope,
)


def _certificates(tmp_path):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIX Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf(name, usage, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_path = tmp_path / f"{name}.pem"
        key_path = tmp_path / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        return cert_path, key_path

    server_cert, server_key = leaf("localhost", ExtendedKeyUsageOID.SERVER_AUTH, server=True)
    client_cert, client_key = leaf("oix-test-client", ExtendedKeyUsageOID.CLIENT_AUTH)
    return ca_path, server_cert, server_key, client_cert, client_key


def _tls_contexts(tmp_path):
    ca, server_cert, server_key, client_cert, client_key = _certificates(tmp_path)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(server_cert, server_key)
    server.load_verify_locations(cafile=str(ca))
    server.verify_mode = ssl.CERT_REQUIRED
    server.minimum_version = ssl.TLSVersion.TLSv1_2

    client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    client.load_cert_chain(client_cert, client_key)
    client.check_hostname = True
    client.verify_mode = ssl.CERT_REQUIRED
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    return server, client


def test_frame_codec_round_trip_and_rejects_noncanonical_or_duplicate_json():
    async def run():
        frame = encode_frame({"kind": "probe", "value": 7})
        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()
        assert await read_frame(reader) == {"kind": "probe", "value": 7}

        duplicate = b'{"a":1,"a":2}'
        reader = asyncio.StreamReader()
        reader.feed_data(len(duplicate).to_bytes(4, "big") + duplicate)
        reader.feed_eof()
        with pytest.raises(TransportError, match="duplicate"):
            await read_frame(reader)

        noncanonical = b'{ "a": 1 }'
        reader = asyncio.StreamReader()
        reader.feed_data(len(noncanonical).to_bytes(4, "big") + noncanonical)
        reader.feed_eof()
        with pytest.raises(TransportError, match="canonical"):
            await read_frame(reader)

    asyncio.run(run())


def test_frame_codec_rejects_oversized_and_truncated_frames():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        with pytest.raises(TransportError, match="length"):
            await read_frame(reader)

        reader = asyncio.StreamReader()
        reader.feed_data((10).to_bytes(4, "big") + b"{}")
        reader.feed_eof()
        with pytest.raises(TransportError, match="truncated"):
            await read_frame(reader)

    asyncio.run(run())


def test_mutual_tls_transport_accepts_and_acknowledges_once(tmp_path):
    async def run():
        server_tls, client_tls = _tls_contexts(tmp_path)
        sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
        sender_card = generate_identity(sender_dir, "Sender", ["public.research"])
        receiver_card = generate_identity(receiver_dir, "Receiver", ["public.research"])
        sender_key = load_private_key(sender_dir)
        receiver_key = load_private_key(receiver_dir)
        sender_id = sender_card["card"]["agent_id"]
        receiver_id = receiver_card["card"]["agent_id"]

        database = tmp_path / "receiver.sqlite3"
        inbox = SQLiteInbox(
            database, receiver_id, CapabilityPolicy({"public.research"})
        )
        inbox.trust_peer(sender_card)
        prekeys = SQLitePreKeyStore(database)
        bundle = create_prekey_bundle(prekeys, receiver_key, count=2)
        server = OIXMutualTLSServer(inbox, prekeys, receiver_key)

        with pytest.raises(ValueError, match="non-loopback"):
            await server.start(
                host="0.0.0.0", port=0, ssl_context=server_tls
            )
        host, port = await server.start(ssl_context=server_tls)
        try:
            message = create_message(
                sender_key,
                receiver_id,
                "task.request",
                {"task": "public-source verification"},
                capability="public.research",
            )
            encrypted = encrypt_prekey_envelope(
                message, bundle, receiver_key.public_key().public_bytes_raw()
            )
            args = {
                "host": host,
                "port": port,
                "server_hostname": "localhost",
                "ssl_context": client_tls,
                "local_agent_id": sender_id,
                "expected_peer_agent_id": receiver_id,
                "expected_message_id": message["body"]["message_id"],
                "expected_peer_signing_public_key": receiver_key.public_key().public_bytes_raw(),
            }
            first = await send_encrypted_envelope(encrypted, **args)
            second = await send_encrypted_envelope(encrypted, **args)
            assert first == second
            assert first["body"]["type"] == "delivery.receipt"
            assert inbox.pending_work()[0]["status"] == "pending_approval"
            assert prekeys.available_count(now=int(datetime.now(timezone.utc).timestamp())) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_server_requires_mutual_tls_and_loopback_default(tmp_path):
    async def run():
        _, client_tls = _tls_contexts(tmp_path)
        no_client_auth = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with pytest.raises(ValueError, match="trusted client certificate"):
            from oix.transport import _require_server_tls
            _require_server_tls(no_client_auth)
        with pytest.raises(ValueError, match="hostname"):
            from oix.transport import _require_client_tls
            invalid_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            invalid_client.check_hostname = False
            _require_client_tls(invalid_client)

    asyncio.run(run())
