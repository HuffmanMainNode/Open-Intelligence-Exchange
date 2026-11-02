"""Phase 16: two independently configured OIX nodes exchange signed discovery data.

This is a reproducible local multi-process harness. Each node owns a distinct
Ed25519 identity, TLS leaf certificate, SQLite database, and process. A temporary
test CA is shared only as an explicitly configured trust root for this demo.
No endpoint in a discovery record is fetched or contacted.
"""
from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import queue
import ssl
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from oix.discovery import SQLiteDiscoveryStore, create_announcement
from oix.discovery_exchange import create_exchange_batch
from oix.identity import generate_identity, load_private_key
from oix.transport import (
    OIXDiscoveryExchangeServer,
    agent_identity_uri,
    send_discovery_exchange,
)


def _write_key(path: Path, key: Any) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        path.chmod(0o600)


def _issue_certificate(
    ca_key: Any,
    ca_name: x509.Name,
    *,
    common_name: str,
    agent_id: str,
    usage: x509.ObjectIdentifier,
    server: bool,
    directory: Path,
) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC).replace(tzinfo=None)
    names: list[x509.GeneralName] = [
        x509.UniformResourceIdentifier(agent_identity_uri(agent_id))
    ]
    if server:
        names.append(x509.DNSName("localhost"))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = directory / f"{common_name}.pem"
    key_path = directory / f"{common_name}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    return cert_path, key_path


def _create_test_pki(root: Path, node_a_id: str, node_b_id: str) -> dict[str, Path]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIX Phase 16 Ephemeral Test CA")])
    now = datetime.now(UTC).replace(tzinfo=None)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = root / "test-ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    a_cert, a_key = _issue_certificate(
        ca_key, ca_name, common_name="node-a-client", agent_id=node_a_id,
        usage=ExtendedKeyUsageOID.CLIENT_AUTH, server=False, directory=root,
    )
    b_cert, b_key = _issue_certificate(
        ca_key, ca_name, common_name="localhost", agent_id=node_b_id,
        usage=ExtendedKeyUsageOID.SERVER_AUTH, server=True, directory=root,
    )
    return {
        "ca": ca_path, "a_cert": a_cert, "a_key": a_key,
        "b_cert": b_cert, "b_key": b_key,
    }


def _server_context(paths: dict[str, Path]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(paths["b_cert"]), str(paths["b_key"]))
    context.load_verify_locations(cafile=str(paths["ca"]))
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _client_context(paths: dict[str, Path]) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(paths["ca"]))
    context.load_cert_chain(str(paths["a_cert"]), str(paths["a_key"]))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


async def _serve_node_b(
    database: str,
    approved_relay_id: str,
    cert_paths: dict[str, str],
    ready: Any,
    stop: Any,
) -> None:
    paths = {key: Path(value) for key, value in cert_paths.items()}
    store = SQLiteDiscoveryStore(database)
    server = OIXDiscoveryExchangeServer(
        store,
        approved_relay_agent_ids={approved_relay_id},
    )
    host, port = await server.start(
        host="127.0.0.1",
        port=0,
        ssl_context=_server_context(paths),
    )
    ready.put({"ok": True, "host": host, "port": port})
    try:
        await asyncio.to_thread(stop.wait)
    finally:
        await server.close()


def _node_b_process(
    database: str,
    approved_relay_id: str,
    cert_paths: dict[str, str],
    ready: Any,
    stop: Any,
) -> None:
    try:
        asyncio.run(_serve_node_b(database, approved_relay_id, cert_paths, ready, stop))
    except Exception as exc:
        ready.put({"ok": False, "error": type(exc).__name__})
        raise


async def _send_from_node_a(
    database: str,
    identity_dir: str,
    batch_path: str,
    host: str,
    port: int,
    expected_peer_id: str,
    cert_paths: dict[str, str],
) -> dict[str, Any]:
    paths = {key: Path(value) for key, value in cert_paths.items()}
    # Node A maintains its own independent local discovery database.
    local_store = SQLiteDiscoveryStore(database)
    batch = json.loads(Path(batch_path).read_text(encoding="utf-8"))
    announcement = batch["exchange"]["records"][0]["announcement"]
    card = batch["exchange"]["records"][0]["card"]
    local_store.record(announcement, card, now=int(time.time()))
    return await send_discovery_exchange(
        batch,
        host=host,
        port=port,
        server_hostname="localhost",
        ssl_context=_client_context(paths),
        expected_peer_agent_id=expected_peer_id,
    )


def _node_a_process(
    database: str,
    identity_dir: str,
    batch_path: str,
    host: str,
    port: int,
    expected_peer_id: str,
    cert_paths: dict[str, str],
    result_queue: Any,
) -> None:
    try:
        result = asyncio.run(_send_from_node_a(
            database, identity_dir, batch_path, host, port,
            expected_peer_id, cert_paths,
        ))
        result_queue.put({"ok": True, "ack": result})
    except Exception as exc:  # noqa: BLE001
        result_queue.put({"ok": False, "error": type(exc).__name__})


def main() -> None:
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="oix-phase16-") as temporary:
        root = Path(temporary)
        node_a_dir, node_b_dir = root / "node-a-identity", root / "node-b-identity"
        node_a_card = generate_identity(node_a_dir, "Independent Node A", ["public.research"])
        node_b_card = generate_identity(node_b_dir, "Independent Node B", ["public.research"])
        node_a_id = node_a_card["card"]["agent_id"]
        node_b_id = node_b_card["card"]["agent_id"]
        now = int(time.time())
        signed_announcement = create_announcement(
            load_private_key(node_a_dir),
            node_a_card,
            ["https://node-a.invalid/oix/discovery"],
            sequence=1,
            now=now,
            ttl=300,
        )
        batch = create_exchange_batch(
            [{"announcement": signed_announcement, "card": node_a_card}],
            now=now,
        )
        batch_path = root / "batch.json"
        batch_path.write_text(json.dumps(batch), encoding="utf-8")
        paths = _create_test_pki(root, node_a_id, node_b_id)
        cert_paths = {key: str(value) for key, value in paths.items()}

        node_a_db = root / "node-a" / "discovery.sqlite3"
        node_b_db = root / "node-b" / "discovery.sqlite3"
        ready = context.Queue()
        result_queue = context.Queue()
        stop = context.Event()
        receiver = context.Process(
            target=_node_b_process,
            args=(str(node_b_db), node_a_id, cert_paths, ready, stop),
            name="oix-node-b",
        )
        sender: multiprocessing.Process | None = None
        receiver.start()
        try:
            try:
                server_info = ready.get(timeout=15)
            except queue.Empty as exc:
                raise RuntimeError("Node B did not become ready") from exc
            if not server_info.get("ok"):
                raise RuntimeError(f"Node B startup failed: {server_info.get('error')}")
            sender = context.Process(
                target=_node_a_process,
                args=(
                    str(node_a_db), str(node_a_dir), str(batch_path),
                    server_info["host"], server_info["port"], node_b_id,
                    cert_paths, result_queue,
                ),
                name="oix-node-a",
            )
            sender.start()
            sender.join(timeout=20)
            if sender.is_alive():
                sender.terminate()
                sender.join(timeout=5)
                raise RuntimeError("Node A exchange timed out")
            if sender.exitcode != 0:
                raise RuntimeError(f"Node A exited with status {sender.exitcode}")
            try:
                sender_result = result_queue.get(timeout=5)
            except queue.Empty as exc:
                raise RuntimeError("Node A did not return an exchange result") from exc
            if not sender_result.get("ok"):
                raise RuntimeError(f"Node A exchange failed: {sender_result.get('error')}")
        finally:
            stop.set()
            receiver.join(timeout=10)
            if receiver.is_alive():
                receiver.terminate()
                receiver.join(timeout=5)
        if receiver.exitcode != 0:
            raise RuntimeError(f"Node B exited with status {receiver.exitcode}")

        node_a_store = SQLiteDiscoveryStore(node_a_db)
        node_b_store = SQLiteDiscoveryStore(node_b_db)
        node_a_records = node_a_store.active(now=int(time.time()))
        node_b_records = node_b_store.active(now=int(time.time()))
        if node_a_db.resolve() == node_b_db.resolve():
            raise RuntimeError("nodes unexpectedly share a database path")
        if len(node_a_records) != 1 or len(node_b_records) != 1:
            raise RuntimeError("independent node stores do not contain the expected record")
        if node_a_records[0]["agent_id"] != node_a_id or node_b_records[0]["agent_id"] != node_a_id:
            raise RuntimeError("node stores disagree on the discovered agent identity")
        if node_b_records[0]["trust_state"] != "discovered_untrusted":
            raise RuntimeError("discovered subject was unexpectedly trusted")
        ack = sender_result["ack"]
        if ack["accepted_count"] != 1 or ack["rejected_count"] != 0:
            raise RuntimeError("Node B acknowledgement does not report one accepted record")

        print("OIX Phase 16 independent multi-node exchange: PASS")
        print("processes: 2 independent OS processes")
        print("identities: 2 independent Ed25519 identities")
        print("databases: 2 separate SQLite files")
        print("transport: mutual TLS with OIX URI SAN identity binding")
        print("authorization: receiver approved only Node A as relay")
        print("acknowledgement: exact batch ID and digest verified")
        print("discovery trust state: discovered_untrusted")
        print("endpoint behavior: advertised endpoint was not contacted")
        print("network scope: loopback test only; no WAN claim")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
