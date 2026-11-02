from __future__ import annotations

import asyncio
import ipaddress
import ssl
from datetime import UTC, datetime, timedelta

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
    agent_identity_uri,
    encode_frame,
    read_frame,
    send_encrypted_envelope,
    send_encrypted_stream,
)


def _certificates(tmp_path, server_agent_id, client_agent_id):
    now = datetime.now(UTC)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf(name, usage, agent_id, server=False):
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
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        san_names = [x509.UniformResourceIdentifier(agent_identity_uri(agent_id))]
        if server:
            san_names.extend([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ])
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
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

    server_cert, server_key = leaf(
        "localhost", ExtendedKeyUsageOID.SERVER_AUTH, server_agent_id, server=True
    )
    client_cert, client_key = leaf(
        "oix-test-client", ExtendedKeyUsageOID.CLIENT_AUTH, client_agent_id
    )
    return ca_path, server_cert, server_key, client_cert, client_key


def _tls_contexts(tmp_path, server_agent_id, client_agent_id):
    ca, server_cert, server_key, client_cert, client_key = _certificates(
        tmp_path, server_agent_id, client_agent_id
    )
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
        sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
        sender_card = generate_identity(sender_dir, "Sender", ["public.research"])
        receiver_card = generate_identity(receiver_dir, "Receiver", ["public.research"])
        sender_key = load_private_key(sender_dir)
        receiver_key = load_private_key(receiver_dir)
        sender_id = sender_card["card"]["agent_id"]
        receiver_id = receiver_card["card"]["agent_id"]
        server_tls, client_tls = _tls_contexts(tmp_path, receiver_id, sender_id)

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
            assert prekeys.available_count(now=int(datetime.now(UTC).timestamp())) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_server_requires_mutual_tls_and_loopback_default(tmp_path):
    async def run():
        dummy_server = "ed25519:" + "1" * 64
        dummy_client = "ed25519:" + "2" * 64
        _, _client_tls = _tls_contexts(tmp_path, dummy_server, dummy_client)
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


def test_server_rejects_client_certificate_bound_to_different_oix_agent(tmp_path):
    async def run():
        sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
        sender_card = generate_identity(sender_dir, "Sender", ["public.research"])
        receiver_card = generate_identity(receiver_dir, "Receiver", ["public.research"])
        sender_key, receiver_key = load_private_key(sender_dir), load_private_key(receiver_dir)
        sender_id = sender_card["card"]["agent_id"]
        receiver_id = receiver_card["card"]["agent_id"]
        wrong_client_id = "ed25519:" + "0" * 64
        if wrong_client_id == sender_id:
            wrong_client_id = "ed25519:" + "f" * 64
        server_tls, wrong_client_tls = _tls_contexts(
            tmp_path, receiver_id, wrong_client_id
        )
        database = tmp_path / "receiver.sqlite3"
        inbox = SQLiteInbox(database, receiver_id, CapabilityPolicy({"public.research"}))
        inbox.trust_peer(sender_card)
        prekeys = SQLitePreKeyStore(database)
        bundle = create_prekey_bundle(prekeys, receiver_key, count=1)
        server = OIXMutualTLSServer(inbox, prekeys, receiver_key)
        host, port = await server.start(ssl_context=server_tls)
        try:
            message = create_message(
                sender_key,
                receiver_id,
                "task.request",
                {"task": "must not be accepted"},
                capability="public.research",
            )
            encrypted = encrypt_prekey_envelope(
                message, bundle, receiver_key.public_key().public_bytes_raw()
            )
            with pytest.raises(TransportError, match="truncated"):
                await send_encrypted_envelope(
                    encrypted,
                    host=host,
                    port=port,
                    server_hostname="localhost",
                    ssl_context=wrong_client_tls,
                    local_agent_id=sender_id,
                    expected_peer_agent_id=receiver_id,
                    expected_message_id=message["body"]["message_id"],
                    expected_peer_signing_public_key=receiver_key.public_key().public_bytes_raw(),
                )
            assert inbox.pending_work() == []
            assert prekeys.available_count(now=int(datetime.now(UTC).timestamp())) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_client_rejects_tls_server_certificate_bound_to_different_oix_agent(tmp_path):
    async def run():
        sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
        sender_card = generate_identity(sender_dir, "Sender", ["public.research"])
        receiver_card = generate_identity(receiver_dir, "Receiver", ["public.research"])
        sender_key, receiver_key = load_private_key(sender_dir), load_private_key(receiver_dir)
        sender_id = sender_card["card"]["agent_id"]
        receiver_id = receiver_card["card"]["agent_id"]
        wrong_server_id = "ed25519:" + "0" * 64
        if wrong_server_id == receiver_id:
            wrong_server_id = "ed25519:" + "f" * 64
        server_tls, client_tls = _tls_contexts(tmp_path, wrong_server_id, sender_id)
        database = tmp_path / "receiver.sqlite3"
        inbox = SQLiteInbox(database, receiver_id, CapabilityPolicy({"public.research"}))
        inbox.trust_peer(sender_card)
        prekeys = SQLitePreKeyStore(database)
        bundle = create_prekey_bundle(prekeys, receiver_key, count=1)
        server = OIXMutualTLSServer(inbox, prekeys, receiver_key)
        host, port = await server.start(ssl_context=server_tls)
        try:
            message = create_message(
                sender_key,
                receiver_id,
                "task.request",
                {"task": "must not be sent"},
                capability="public.research",
            )
            encrypted = encrypt_prekey_envelope(
                message, bundle, receiver_key.public_key().public_bytes_raw()
            )
            with pytest.raises(TransportError, match="TLS server certificate identity"):
                await send_encrypted_envelope(
                    encrypted,
                    host=host,
                    port=port,
                    server_hostname="localhost",
                    ssl_context=client_tls,
                    local_agent_id=sender_id,
                    expected_peer_agent_id=receiver_id,
                    expected_message_id=message["body"]["message_id"],
                    expected_peer_signing_public_key=receiver_key.public_key().public_bytes_raw(),
                )
            assert inbox.pending_work() == []
            assert prekeys.available_count(now=int(datetime.now(UTC).timestamp())) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_mutual_tls_stream_delivers_multiple_messages_on_one_connection(tmp_path):
    async def run():
        sender_dir, receiver_dir = tmp_path / "sender", tmp_path / "receiver"
        sender_card = generate_identity(sender_dir, "Streaming Sender", ["public.research"])
        receiver_card = generate_identity(receiver_dir, "Streaming Receiver", ["public.research"])
        sender_key, receiver_key = load_private_key(sender_dir), load_private_key(receiver_dir)
        sender_id = sender_card["card"]["agent_id"]
        receiver_id = receiver_card["card"]["agent_id"]
        server_tls, client_tls = _tls_contexts(tmp_path, receiver_id, sender_id)

        database = tmp_path / "receiver.sqlite3"
        inbox = SQLiteInbox(database, receiver_id, CapabilityPolicy({"public.research"}))
        inbox.trust_peer(sender_card)
        prekeys = SQLitePreKeyStore(database)
        bundle = create_prekey_bundle(prekeys, receiver_key, count=3)
        server = OIXMutualTLSServer(
            inbox,
            prekeys,
            receiver_key,
            idle_timeout_seconds=2,
            max_messages_per_connection=3,
        )
        host, port = await server.start(ssl_context=server_tls)
        try:
            messages = [
                create_message(
                    sender_key,
                    receiver_id,
                    "task.request",
                    {"task": f"public research item {index}"},
                    capability="public.research",
                )
                for index in range(2)
            ]
            encrypted = [
                encrypt_prekey_envelope(
                    message, bundle, receiver_key.public_key().public_bytes_raw()
                )
                for message in messages
            ]
            receipts = await send_encrypted_stream(
                encrypted,
                expected_message_ids=[
                    message["body"]["message_id"] for message in messages
                ],
                host=host,
                port=port,
                server_hostname="localhost",
                ssl_context=client_tls,
                local_agent_id=sender_id,
                expected_peer_agent_id=receiver_id,
                expected_peer_signing_public_key=receiver_key.public_key().public_bytes_raw(),
            )
            assert len(receipts) == 2
            assert all(item["body"]["type"] == "delivery.receipt" for item in receipts)
            pending = inbox.pending_work()
            assert len(pending) == 2
            assert {
                item["message_id"] for item in pending
            } == {message["body"]["message_id"] for message in messages}
            assert prekeys.available_count(now=int(datetime.now(UTC).timestamp())) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_stream_rejects_mismatched_message_id_list_before_connecting():
    async def run():
        with pytest.raises(ValueError, match="matching items"):
            await send_encrypted_stream(
                [{"header": {"sender": "a", "recipient": "b"}}],
                expected_message_ids=[],
                host="127.0.0.1",
                port=1,
                server_hostname="localhost",
                ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
                local_agent_id="a",
                expected_peer_agent_id="b",
                expected_peer_signing_public_key=b"",
            )

    asyncio.run(run())
