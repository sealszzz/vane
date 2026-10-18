#!/usr/bin/env python3
"""Process-level smoke test for Vane TCP/UDP routing.

Uses only the Python standard library except for QUIC Initial generation, which
is enabled when the `cryptography` package is available.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import queue
import signal
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
_RESERVED_PORTS: set[int] = set()


def vane_command(binary: str, *args: str) -> list[str]:
    """Run test instances through an optional cross-architecture runner."""
    runner = shlex.split(os.environ.get("VANE_TEST_RUNNER", ""))
    command = [*runner, binary, *args]
    taskset = shutil.which("taskset")
    if taskset is not None and hasattr(os, "sched_getaffinity"):
        cpus = sorted(os.sched_getaffinity(0))
        if cpus:
            return [taskset, "-c", str(cpus[0]), *command]
    return command


def reserve_port(sock_type: int) -> int:
    # Binding to port zero and closing immediately does not guarantee that the
    # next call receives a different ephemeral port.  Keep this test run's
    # selections unique so multiple marker servers cannot race for one port.
    for _ in range(128):
        sock = socket.socket(socket.AF_INET, sock_type)
        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        finally:
            sock.close()
        if port not in _RESERVED_PORTS:
            _RESERVED_PORTS.add(port)
            return port
    raise RuntimeError("could not reserve a unique test port")


def make_tls_handshake(host: Optional[str], padding_bytes: int = 0) -> bytes:
    body = bytearray(b"\x03\x03" + b"\x00" * 32)
    body += b"\x00"                 # session ID length
    body += b"\x00\x02\x13\x01" # cipher suites
    body += b"\x01\x00"           # compression methods
    extensions = bytearray()
    if host is not None:
        encoded = host.encode("ascii")
        server_name = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
        name_list = len(server_name).to_bytes(2, "big") + server_name
        extensions += b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list
    if padding_bytes:
        if padding_bytes > 60000:
            raise ValueError("test TLS padding is too large")
        extensions += b"\x00\x15" + padding_bytes.to_bytes(2, "big") + b"\x00" * padding_bytes
    body += len(extensions).to_bytes(2, "big") + extensions
    return b"\x01" + len(body).to_bytes(3, "big") + body


def make_tls_record(host: Optional[str], padding_bytes: int = 0) -> bytes:
    handshake = make_tls_handshake(host, padding_bytes)
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return bytes(output[:length])


def hkdf_label(length: int, label: bytes) -> bytes:
    full_label = b"tls13 " + label
    return length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00"


def encode_varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    raise ValueError("QUIC varint too large for test")


def make_quic_initial(host: str, version: int, *, scid: bytes | None = None,
                      dcid: bytes | None = None,
                      crypto_limit: int | None = None) -> bytes:
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError("cryptography is unavailable")
    if version == 1:
        salt = QUIC_V1_SALT
        version_bytes = b"\x00\x00\x00\x01"
        first = 0xC1
        key_label, iv_label, hp_label = b"quic key", b"quic iv", b"quic hp"
    elif version == 2:
        salt = QUIC_V2_SALT
        version_bytes = b"\x6b\x33\x43\xcf"
        first = 0xD1
        key_label, iv_label, hp_label = b"quicv2 key", b"quicv2 iv", b"quicv2 hp"
    else:
        raise ValueError("unsupported QUIC version")

    if dcid is None:
        dcid = bytes.fromhex("8394c8f03e515708")
    if scid is None:
        scid = bytes.fromhex("0102030405060708")
    if not (0 <= len(dcid) <= 20 and 0 <= len(scid) <= 20):
        raise ValueError("QUIC connection IDs must be at most 20 bytes")
    initial_secret = hkdf_extract(salt, dcid)
    client_secret = hkdf_expand(initial_secret, hkdf_label(32, b"client in"), 32)
    key = hkdf_expand(client_secret, hkdf_label(16, key_label), 16)
    iv = hkdf_expand(client_secret, hkdf_label(12, iv_label), 12)
    hp = hkdf_expand(client_secret, hkdf_label(16, hp_label), 16)

    crypto = make_tls_handshake(host)
    if crypto_limit is not None:
        if not (4 <= crypto_limit < len(crypto)):
            raise ValueError("crypto_limit must retain an incomplete TLS handshake")
        crypto = crypto[:crypto_limit]
    frame = b"\x06" + encode_varint(0) + encode_varint(len(crypto)) + crypto
    # Exactly 1200 bytes on the wire. The long-header fields below are fixed-size
    # for this fixture, so plaintext length 1156 yields a 1200-byte datagram.
    plaintext = frame + b"\x00" * (1156 - len(frame))
    pn = 0
    pn_bytes = pn.to_bytes(2, "big")
    protected_len = len(pn_bytes) + len(plaintext) + 16
    header_without_pn = (
        bytes([first]) + version_bytes + bytes([len(dcid)]) + dcid +
        bytes([len(scid)]) + scid + encode_varint(0) + encode_varint(protected_len)
    )
    aad = header_without_pn + pn_bytes
    nonce = bytearray(iv)
    pn64 = pn.to_bytes(8, "big")
    for i, value in enumerate(pn64):
        nonce[4 + i] ^= value
    ciphertext = AESGCM(key).encrypt(bytes(nonce), plaintext, aad)
    packet = bytearray(aad + ciphertext)
    pn_offset = len(header_without_pn)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    packet[0] ^= mask[0] & 0x0F
    for i in range(2):
        packet[pn_offset + i] ^= mask[i + 1]
    assert len(packet) == 1200
    return bytes(packet)


def recv_all(sock: socket.socket) -> bytes:
    output = bytearray()
    while True:
        data = sock.recv(65536)
        if not data:
            return bytes(output)
        output += data


@dataclass
class TcpMarkerServer:
    port: int
    marker: bytes
    expect_proxy: bool = False
    response_tos: Optional[int] = None
    stop: threading.Event = field(default_factory=threading.Event)
    ready: threading.Event = field(default_factory=threading.Event)
    received: queue.Queue[bytes] = field(default_factory=queue.Queue)
    thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=2.0):
            raise RuntimeError("TCP marker server did not start")

    def _run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        listener.settimeout(0.2)
        self.ready.set()
        try:
            while not self.stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(1.0)
                    data = bytearray()
                    try:
                        while len(data) < 5 or (self.expect_proxy and len(data) < 28):
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                    except socket.timeout:
                        pass
                    self.received.put(bytes(data))
                    conn.sendall(self.marker)
        finally:
            listener.close()

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1.0)


@dataclass
class UdpMarkerServer:
    port: int
    marker: bytes
    expect_proxy: bool = False
    response_tos: Optional[int] = None
    stop: threading.Event = field(default_factory=threading.Event)
    ready: threading.Event = field(default_factory=threading.Event)
    received: queue.Queue[bytes] = field(default_factory=queue.Queue)
    peers: queue.Queue[tuple[str, int]] = field(default_factory=queue.Queue)
    thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=2.0):
            raise RuntimeError("UDP marker server did not start")

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.response_tos is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, self.response_tos)
        sock.bind(("127.0.0.1", self.port))
        sock.settimeout(0.2)
        self.ready.set()
        try:
            while not self.stop.is_set():
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                self.received.put(data)
                self.peers.put(peer)
                sock.sendto(self.marker, peer)
        finally:
            sock.close()

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1.0)


def tcp_request(port: int, payload: bytes, timeout: float = 2.0) -> bytes:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    result = recv_all(sock)
    sock.close()
    return result


def udp_request(port: int, payload: bytes, timeout: float = 2.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(payload, ("127.0.0.1", port))
    result, _ = sock.recvfrom(65535)
    sock.close()
    return result


def udp_request_with_tos(port: int, payload: bytes, timeout: float = 2.0) -> tuple[bytes, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    sock.settimeout(timeout)
    sock.sendto(payload, ("127.0.0.1", port))
    result, ancillary, _, _ = sock.recvmsg(65535, 128)
    sock.close()
    values = [data[0] for level, kind, data in ancillary
              if level == socket.IPPROTO_IP and kind == socket.IP_TOS and data]
    assert values, ancillary
    return result, values[-1]


def wait_ready(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=1)
            raise RuntimeError(f"Vane exited during startup:\n{stderr}")
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            sock.close()
            return
        except OSError:
            time.sleep(0.03)
    raise RuntimeError("Vane listener did not become ready")


def wait_udp_ready(process: subprocess.Popen[str], port: int,
                   upstream: UdpMarkerServer) -> None:
    """Wait until the public UDP listener and its worker path are usable."""
    probe = b"vane-udp-readiness"
    deadline = time.monotonic() + 4.0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, stderr = process.communicate(timeout=1)
                raise RuntimeError(f"Vane exited during UDP startup:\n{stderr}")
            sock.sendto(probe, ("127.0.0.1", port))
            try:
                response, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if response != upstream.marker:
                raise RuntimeError(f"unexpected UDP readiness response: {response!r}")

            # The retry is test setup, not a smoke-test assertion. Remove every
            # identical copy from the marker-server queues before test traffic.
            time.sleep(0.02)
            received = 0
            while True:
                try:
                    observed = upstream.received.get_nowait()
                except queue.Empty:
                    break
                if observed != probe:
                    raise RuntimeError(f"unexpected UDP readiness payload: {observed!r}")
                received += 1
            if received == 0:
                raise RuntimeError("UDP readiness response had no upstream request")
            for _ in range(received):
                try:
                    upstream.peers.get_nowait()
                except queue.Empty as exc:
                    raise RuntimeError("UDP readiness queues are inconsistent") from exc
            try:
                upstream.peers.get_nowait()
            except queue.Empty:
                pass
            else:
                raise RuntimeError("UDP readiness queues are inconsistent")
            return
    finally:
        sock.close()
    raise RuntimeError("Vane UDP forwarding path did not become ready")


def assert_proxy_packet(data: bytes, transport_nibble: int) -> None:
    assert data.startswith(PROXY_V2_SIGNATURE), data[:16].hex()
    assert len(data) >= 16
    assert data[13] & 0x0F == transport_nibble
    address_len = int.from_bytes(data[14:16], "big")
    header_len = 16 + address_len
    assert len(data) > header_len


def run(binary: str) -> None:
    public_port = reserve_port(socket.SOCK_STREAM)
    tcp_exact = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-EXACT", True)
    tcp_wild = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-WILD")
    tcp_none = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-NONE")
    tcp_any = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-ANY")
    tcp_fallback = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-FALLBACK")
    udp_exact = UdpMarkerServer(reserve_port(socket.SOCK_DGRAM), b"UDP-EXACT", True)
    udp_nextquic = UdpMarkerServer(reserve_port(socket.SOCK_DGRAM), b"UDP-NEXTQUIC")
    udp_any = UdpMarkerServer(reserve_port(socket.SOCK_DGRAM), b"UDP-ANY")
    udp_fallback = UdpMarkerServer(reserve_port(socket.SOCK_DGRAM), b"UDP-FALLBACK",
                                   response_tos=0x02)
    servers = [tcp_exact, tcp_wild, tcp_none, tcp_any, tcp_fallback,
               udp_exact, udp_nextquic, udp_any, udp_fallback]
    for server in servers:
        server.start()

    config = {
        "logging": {"level": "info"},
        "listeners": [
            {
                "address": f"[::]:{public_port}",
                "transport": "tcp",
                "targets": [
                    {"location": "drop", "sni": ["blocked.example"]},
                    {"location": f"127.0.0.1:{tcp_exact.port}", "proxy_protocol": True,
                     "sni": ["exact.example"]},
                    {"location": f"127.0.0.1:{tcp_wild.port}", "sni": ["*.example.net"]},
                    {"location": f"127.0.0.1:{tcp_none.port}", "sni": ["none"]},
                    {"location": f"127.0.0.1:{tcp_any.port}", "sni": ["any"]},
                    {"location": f"127.0.0.1:{tcp_fallback.port}"},
                ],
            },
            {
                "address": f"[::]:{public_port}",
                "transport": "udp",
                "targets": [
                    {"location": "drop", "sni": ["blocked.example"]},
                    {"location": f"127.0.0.1:{udp_exact.port}", "proxy_protocol": True,
                     "sni": ["exact.example"]},
                    {"location": f"127.0.0.1:{udp_nextquic.port}",
                     "sni": ["localhost"]},
                    {"location": f"127.0.0.1:{udp_any.port}", "sni": ["any", "none"]},
                    {"location": f"127.0.0.1:{udp_fallback.port}"},
                ],
            },
        ],
    }

    fd, config_path = tempfile.mkstemp(prefix="vane-integration-", suffix=".json")
    os.close(fd)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle)

    checked = subprocess.run(
        vane_command(binary, "--check", config_path), capture_output=True, text=True, timeout=3.0,
    )
    assert checked.returncode == 0, checked
    assert "warnings=1" in checked.stdout, checked.stdout
    assert (
        "UDP listener" in checked.stderr and
        "proxy_protocol=true" in checked.stderr
    ), checked.stderr

    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    process = subprocess.Popen(
        vane_command(binary, config_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        wait_ready(process, public_port)
        wait_udp_ready(process, public_port, udp_fallback)

        assert tcp_request(public_port, b"GET / HTTP/1.0\r\n\r\n") == b"TCP-FALLBACK"
        assert tcp_request(public_port, make_tls_record("exact.example")) == b"TCP-EXACT"
        exact_wire = tcp_exact.received.get(timeout=1.0)
        assert_proxy_packet(exact_wire, 0x01)
        assert int.from_bytes(exact_wire[14:16], "big") == 12
        proxy_len = 16 + int.from_bytes(exact_wire[14:16], "big")
        assert exact_wire[proxy_len:proxy_len + 3] == b"\x16\x03\x03"

        # Force the TLS probe buffer to grow beyond the 16 KiB steady relay block.
        assert tcp_request(public_port, make_tls_record("exact.example", 20000)) == b"TCP-EXACT"
        grown_wire = tcp_exact.received.get(timeout=1.0)
        assert_proxy_packet(grown_wire, 0x01)

        assert tcp_request(public_port, make_tls_record("a.b.example.net")) == b"TCP-WILD"
        assert tcp_request(public_port, make_tls_record(None)) == b"TCP-NONE"
        assert tcp_request(public_port, make_tls_record("unknown.example")) == b"TCP-ANY"
        assert tcp_request(public_port, make_tls_record("blocked.example")) == b""

        assert udp_request(public_port, b"plain-udp") == b"UDP-FALLBACK"
        assert udp_request(public_port, b"") == b"UDP-FALLBACK"
        tos_payload, returned_tos = udp_request_with_tos(public_port, b"tos-fallback")
        assert tos_payload == b"UDP-FALLBACK"
        assert returned_tos == 0x02, returned_tos

        # Keep one flow active, then inject an equal-sized burst.  On kernels
        # without UDP_SEGMENT this exercises the active-flow rebatching fallback:
        # the upstream must still receive distinct datagrams, never one merged
        # payload after a failed GSO attempt.
        while True:
            try:
                udp_fallback.received.get_nowait()
            except queue.Empty:
                break
        burst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        burst.settimeout(1.0)
        try:
            burst.sendto(b"batch-seed-000000000000000000000",
                         ("127.0.0.1", public_port))
            response, _ = burst.recvfrom(65535)
            assert response == b"UDP-FALLBACK"
            seed = udp_fallback.received.get(timeout=1.0)
            assert seed == b"batch-seed-000000000000000000000"

            packets = [f"batch-{index:02d}-".encode("ascii") + bytes([65 + index]) * 23
                       for index in range(8)]
            assert len({len(packet) for packet in packets}) == 1
            for packet in packets:
                burst.sendto(packet, ("127.0.0.1", public_port))
            observed = [udp_fallback.received.get(timeout=1.0) for _ in packets]
            assert observed == packets, observed
            for _ in packets:
                response, _ = burst.recvfrom(65535)
                assert response == b"UDP-FALLBACK"
        finally:
            burst.close()

        if HAVE_CRYPTOGRAPHY:
            for version in (1, 2):
                assert udp_request(public_port, make_quic_initial("exact.example", version)) == b"UDP-EXACT"
                exact_datagram = udp_exact.received.get(timeout=1.0)
                assert_proxy_packet(exact_datagram, 0x02)
                assert int.from_bytes(exact_datagram[14:16], "big") == 12
                proxy_len = 16 + int.from_bytes(exact_datagram[14:16], "big")
                assert len(exact_datagram[proxy_len:]) == 1200

            unknown_initial = make_quic_initial("unknown.example", 1)
            assert udp_request(public_port, unknown_initial) == b"UDP-ANY"
            assert udp_any.received.get(timeout=1.0) == unknown_initial

            # A non-Initial datagram may establish a fallback flow before a
            # delayed or reordered QUIC Initial arrives. The Initial must
            # reclassify the existing four-tuple without a process restart.
            reclassify = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            reclassify.settimeout(1.0)
            try:
                plain = b"F" * 1200
                reclassify.sendto(plain, ("127.0.0.1", public_port))
                assert reclassify.recvfrom(65535)[0] == b"UDP-FALLBACK"
                assert udp_fallback.received.get(timeout=1.0) == plain

                # A packet with a syntactically valid Initial header but an
                # invalid protected payload must be dropped and the established
                # fallback flow must remain usable.
                malformed = bytearray(1200)
                malformed[0:5] = b"\xc0\x00\x00\x00\x01"
                malformed[5] = 8
                malformed[6:14] = bytes.fromhex("3132333435363738")
                malformed[14] = 8
                malformed[15:23] = bytes.fromhex("4142434445464748")
                reclassify.sendto(bytes(malformed), ("127.0.0.1", public_port))
                time.sleep(0.05)
                recovery = b"R" * 1200
                reclassify.sendto(recovery, ("127.0.0.1", public_port))
                assert reclassify.recvfrom(65535)[0] == b"UDP-FALLBACK"
                assert udp_fallback.received.get(timeout=1.0) == recovery

                # Keep both datagrams equal-sized and adjacent so this also
                # exercises recvmmsg rebatching and UDP GRO segment paths.
                second_plain = b"G" * 1200
                initial = make_quic_initial(
                    "exact.example", 1,
                    scid=bytes.fromhex("1112131415161718"),
                )
                reclassify.sendto(second_plain, ("127.0.0.1", public_port))
                reclassify.sendto(initial, ("127.0.0.1", public_port))
                replies = set()
                deadline = time.monotonic() + 1.0
                while b"UDP-EXACT" not in replies and time.monotonic() < deadline:
                    try:
                        replies.add(reclassify.recvfrom(65535)[0])
                    except socket.timeout:
                        break
                assert b"UDP-EXACT" in replies, replies
                assert udp_fallback.received.get(timeout=1.0) == second_plain
                exact_wire = udp_exact.received.get(timeout=1.0)
                assert_proxy_packet(exact_wire, 0x02)

                # A side probe must not pause the established connection. Hold
                # an incomplete new Initial, then prove unrelated packets from
                # the old connection still reach the current exact backend.
                pending_scid = bytes.fromhex("3132333435363738")
                pending = make_quic_initial(
                    "exact.example", 1, scid=pending_scid, crypto_limit=64,
                )
                reclassify.settimeout(0.15)
                reclassify.sendto(pending, ("127.0.0.1", public_port))
                try:
                    reclassify.recvfrom(65535)
                    raise AssertionError("incomplete reprobe unexpectedly returned a response")
                except socket.timeout:
                    pass

                old_during_probe = b"P" * 1200
                reclassify.settimeout(1.0)
                reclassify.sendto(old_during_probe, ("127.0.0.1", public_port))
                assert reclassify.recvfrom(65535)[0] == b"UDP-EXACT"
                old_wire = udp_exact.received.get(timeout=1.0)
                assert_proxy_packet(old_wire, 0x02)
                old_proxy_len = 16 + int.from_bytes(old_wire[14:16], "big")
                assert old_wire[old_proxy_len:] == old_during_probe

                completed = make_quic_initial(
                    "exact.example", 1, scid=pending_scid,
                )
                reclassify.sendto(completed, ("127.0.0.1", public_port))
                probe_replies = {
                    reclassify.recvfrom(65535)[0],
                    reclassify.recvfrom(65535)[0],
                }
                assert probe_replies == {b"UDP-EXACT"}
                pending_wire = udp_exact.received.get(timeout=1.0)
                completed_wire = udp_exact.received.get(timeout=1.0)
                assert_proxy_packet(pending_wire, 0x02)
                assert_proxy_packet(completed_wire, 0x02)

                # A valid new Initial whose SNI is explicitly denied must not
                # be allowed to tear down the established exact-route flow.
                denied = make_quic_initial(
                    "blocked.example", 1,
                    scid=bytes.fromhex("191a1b1c1d1e1f20"),
                )
                reclassify.settimeout(0.20)
                reclassify.sendto(denied, ("127.0.0.1", public_port))
                try:
                    reclassify.recvfrom(65535)
                    raise AssertionError("denied reprobe unexpectedly returned a response")
                except socket.timeout:
                    pass

                recovery_exact = b"E" * 1200
                reclassify.settimeout(1.0)
                reclassify.sendto(recovery_exact, ("127.0.0.1", public_port))
                assert reclassify.recvfrom(65535)[0] == b"UDP-EXACT"
                recovery_wire = udp_exact.received.get(timeout=1.0)
                assert_proxy_packet(recovery_wire, 0x02)
                proxy_len = 16 + int.from_bytes(recovery_wire[14:16], "big")
                assert recovery_wire[proxy_len:] == recovery_exact

                # Reuse the same client socket for a new QUIC connection with
                # a different Source Connection ID and SNI. Vane must move
                # the flow from the exact route to the any route atomically.
                moved = make_quic_initial(
                    "unknown.example", 1,
                    scid=bytes.fromhex("2122232425262728"),
                )
                reclassify.sendto(moved, ("127.0.0.1", public_port))
                assert reclassify.recvfrom(65535)[0] == b"UDP-ANY"
                assert udp_any.received.get(timeout=1.0) == moved
            finally:
                reclassify.close()

            blocked = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            blocked.settimeout(0.35)
            blocked.sendto(make_quic_initial("blocked.example", 1), ("127.0.0.1", public_port))
            try:
                blocked.recvfrom(65535)
                raise AssertionError("drop route unexpectedly returned a UDP response")
            except socket.timeout:
                pass
            finally:
                blocked.close()
        else:
            print("SKIP: QUIC process tests require Python cryptography")

        # Real ngtcp2/NextQUIC Initial datagrams. The first packet contains only
        # part of the CRYPTO stream; the second completes ClientHello/SNI. They
        # must be buffered, classified as localhost, and forwarded byte-for-byte
        # without a PROXY header to an ordinary QUIC upstream.
        with open(os.path.join(FIXTURE_DIR, "nextquic-v1-initial-1.bin"), "rb") as handle:
            nextquic_initial_1 = handle.read()
        with open(os.path.join(FIXTURE_DIR, "nextquic-v1-initial-2.bin"), "rb") as handle:
            nextquic_initial_2 = handle.read()
        nextquic_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        nextquic_client.settimeout(1.0)
        try:
            nextquic_client.sendto(nextquic_initial_1, ("127.0.0.1", public_port))
            nextquic_client.sendto(nextquic_initial_2, ("127.0.0.1", public_port))
            assert udp_nextquic.received.get(timeout=1.0) == nextquic_initial_1
            assert udp_nextquic.received.get(timeout=1.0) == nextquic_initial_2
            upstream_peers = [udp_nextquic.peers.get(timeout=1.0) for _ in range(2)]
            assert upstream_peers[0] == upstream_peers[1]
            responses = [nextquic_client.recvfrom(65535)[0] for _ in range(2)]
            assert responses == [b"UDP-NEXTQUIC", b"UDP-NEXTQUIC"]

            # Client keepalives more frequent than the active socket idle timeout
            # must refresh the deadline. Keep traffic flowing for longer than an
            # expiry scan and prove the upstream source port never changes.
            active_peer = upstream_peers[0]
            for index in range(15):
                keepalive = b"\x40keepalive-" + bytes([index])
                nextquic_client.sendto(keepalive, ("127.0.0.1", public_port))
                assert udp_nextquic.received.get(timeout=1.0) == keepalive
                assert udp_nextquic.peers.get(timeout=1.0) == active_peer
                reply, _ = nextquic_client.recvfrom(65535)
                assert reply == b"UDP-NEXTQUIC"
                time.sleep(0.08)

            # Linux can report ECONNREFUSED asynchronously for an earlier UDP
            # datagram. Closing the flow on that error changes the source port and
            # can force QUIC path validation. Stop and restart the upstream, then
            # prove the same connected socket recovers with an unchanged peer.
            udp_nextquic.close()
            for payload in (b"\x40refused-1", b"\x40refused-2"):
                nextquic_client.sendto(payload, ("127.0.0.1", public_port))
                try:
                    nextquic_client.recvfrom(65535)
                except socket.timeout:
                    pass
                time.sleep(0.05)

            restarted_nextquic = UdpMarkerServer(
                udp_nextquic.port, b"UDP-NEXTQUIC"
            )
            restarted_nextquic.start()
            servers.append(restarted_nextquic)
            recovered = False
            for attempt in range(6):
                payload = b"\x40recovered-" + bytes([attempt])
                nextquic_client.sendto(payload, ("127.0.0.1", public_port))
                try:
                    response, _ = nextquic_client.recvfrom(65535)
                except socket.timeout:
                    time.sleep(0.05)
                    continue
                assert response == b"UDP-NEXTQUIC"
                assert restarted_nextquic.received.get(timeout=1.0) == payload
                assert restarted_nextquic.peers.get(timeout=1.0) == active_peer
                recovered = True
                break
            assert recovered, "UDP flow did not recover after ECONNREFUSED"
        finally:
            nextquic_client.close()

        if process.poll() is not None:
            raise AssertionError("Vane exited before smoke test completion")
        print("Vane process-level TCP/UDP smoke tests passed")
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                f"Vane exited with {process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            )
        os.unlink(config_path)
        for server in servers:
            server.close()




def test_tcp_backpressure(binary: str) -> None:
    public_port = reserve_port(socket.SOCK_STREAM)
    upstream_port = reserve_port(socket.SOCK_STREAM)
    payload = b"C" * (256 * 1024)
    response = b"S" * (256 * 1024)
    received: queue.Queue[bytes] = queue.Queue()
    ready = threading.Event()

    def serve() -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", upstream_port))
        listener.listen(1)
        ready.set()
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5.0)
                time.sleep(0.1)
                data = recv_all(conn)
                received.put(data)
                conn.sendall(response)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(timeout=2.0)
    config = {
        "logging": {"level": "error"},
        "listeners": [{
            "address": f"[::]:{public_port}",
            "transport": "tcp",
            "targets": [
                {"location": "drop", "sni": ["probe-only.example"]},
                {"location": f"127.0.0.1:{upstream_port}",
                 "proxy_protocol": False},
            ],
        }],
    }
    fd, path = tempfile.mkstemp(prefix="vane-backpressure-", suffix=".json")
    os.close(fd)
    process: Optional[subprocess.Popen[str]] = None
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        process = subprocess.Popen(
            vane_command(binary, path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1",
                 "UBSAN_OPTIONS": "halt_on_error=1"},
        )
        wait_ready(process, public_port)
        client = socket.create_connection(("127.0.0.1", public_port), timeout=5.0)
        client.settimeout(5.0)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        assert recv_all(client) == response
        client.close()
        assert received.get(timeout=2.0) == payload
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        if process is not None:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise RuntimeError(
                    f"Vane backpressure test exited with {process.returncode}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                )
        thread.join(timeout=2.0)
        os.unlink(path)

def test_probe_limit(binary: str) -> None:
    public_port = reserve_port(socket.SOCK_STREAM)
    upstream = TcpMarkerServer(reserve_port(socket.SOCK_STREAM), b"TCP-PROBE-FALLBACK")
    upstream.start()
    config = {
        "logging": {"level": "error"},
        "listeners": [{
            "address": f"[::]:{public_port}",
            "transport": "tcp",
            "targets": [
                {"location": "drop", "sni": ["exact.example"]},
                {"location": f"127.0.0.1:{upstream.port}",
                 "proxy_protocol": False},
            ],
        }],
    }
    fd, path = tempfile.mkstemp(prefix="vane-probe-limit-", suffix=".json")
    os.close(fd)
    process: Optional[subprocess.Popen[str]] = None
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        process = subprocess.Popen(
            vane_command(binary, path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1",
                 "UBSAN_OPTIONS": "halt_on_error=1"},
        )
        wait_ready(process, public_port)
        assert tcp_request(public_port, b"plain fallback") == b"TCP-PROBE-FALLBACK"
        assert upstream.received.get(timeout=1.0) == b"plain fallback"

        client = socket.create_connection(("127.0.0.1", public_port), timeout=1.0)
        client.settimeout(1.0)
        # TLS-looking, deliberately incomplete record larger than the configured
        # 64 KiB probe limit. It must be closed, not forwarded through fallback,
        # even though valid ClientHello probes may temporarily grow to that bound.
        client.sendall(b"\x16\x03\x03\xff\xff" + b"X" * (70 * 1024))
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError as exc:
            # Release builds may reject the oversized probe before the client
            # reaches shutdown(); that is the expected outcome.
            if exc.errno not in (107, 104):
                raise
        try:
            assert recv_all(client) == b""
        except ConnectionResetError:
            pass
        client.close()
        time.sleep(0.1)
        try:
            unexpected = upstream.received.get_nowait()
        except queue.Empty:
            unexpected = None
        assert unexpected is None, unexpected
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        if process is not None:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise RuntimeError(
                    f"Vane probe-limit test exited with {process.returncode}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                )
        upstream.close()
        os.unlink(path)

def test_startup_failure(binary: str) -> None:
    blocker = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    blocker.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    blocker.bind(("::", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    config = {
        "listeners": [{
            "address": f"[::]:{port}",
            "transport": "tcp",
            "targets": [{"location": "drop"}],
        }],
    }
    fd, path = tempfile.mkstemp(prefix="vane-startup-failure-", suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        result = subprocess.run(vane_command(binary, path), capture_output=True, text=True, timeout=3.0)
        assert result.returncode != 0, result
        assert "failed to initialize" in result.stderr, result.stderr
    finally:
        blocker.close()
        os.unlink(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    test_startup_failure(binary)
    test_tcp_backpressure(binary)
    test_probe_limit(binary)
    run(binary)


if __name__ == "__main__":
    main()
