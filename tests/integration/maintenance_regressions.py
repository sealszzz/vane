#!/usr/bin/env python3
"""Readiness and QUIC reclassification regressions using actual processes."""
from __future__ import annotations
import contextlib
import errno
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import integration_smoke as smoke

USE_NOTIFY = True


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


@contextlib.contextmanager
def instance(binary: str, config: dict, abstract: bool = False):
    with tempfile.TemporaryDirectory(prefix="vane-ready-") as directory:
        root = Path(directory)
        path = root / "config.json"
        path.write_text(json.dumps(config))
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) if USE_NOTIFY else None
        name = str(root / "notify.sock")
        if abstract:
            name = "@vane-" + os.urandom(12).hex()
        if notify is not None:
            notify.bind("\0" + name[1:] if abstract else name)
            notify.settimeout(3)
        env = dict(os.environ)
        env.pop("NOTIFY_SOCKET", None)
        if notify is not None:
            env["NOTIFY_SOCKET"] = name
        with (root / "log").open("w+") as log:
            process = subprocess.Popen(smoke.vane_command(binary, str(path)),
                stdout=log, stderr=log, env=env)
            try:
                if notify is not None:
                    assert notify.recv(256) == b"READY=1"
                else:
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        assert process.poll() is None
                        log.seek(0)
                        if "started address=" in log.read():
                            break
                        time.sleep(.02)
                    else:
                        raise AssertionError("listener did not start")
                assert process.poll() is None
                yield process
            except BaseException:
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                stop_process(process)
                if notify is not None:
                    notify.close()
            assert process.returncode == 0, process.returncode


def test_readiness(binary: str) -> None:
    port = smoke.reserve_port(socket.SOCK_STREAM)
    config = {"logging": {"level": "info"}, "listeners": [{
        "transport": "tcp", "address": f"127.0.0.1:{port}",
        "targets": [{"location": "drop"}],
    }]}
    with instance(binary, config):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
    if not USE_NOTIFY:
        return
    with tempfile.TemporaryDirectory(prefix="vane-fail-") as directory:
        path = Path(directory) / "config.json"
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        name = str(Path(directory) / "notify.sock")
        notify.bind(name)
        notify.settimeout(.1)
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Do not reuse the successful listener's port: the preceding TCP
        # connection can leave it in TIME_WAIT, making this bind flaky.
        # Keep a fresh kernel-assigned port bound throughout the failure test.
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        blocked_port = blocker.getsockname()[1]
        blocked_config = {**config, "listeners": [
            {**config["listeners"][0],
             "address": f"127.0.0.1:{blocked_port}"},
        ]}
        path.write_text(json.dumps(blocked_config))
        try:
            result = subprocess.run(smoke.vane_command(binary, str(path)),
                env={**os.environ, "NOTIFY_SOCKET": name}, capture_output=True,
                text=True, timeout=3)
            assert result.returncode != 0
            assert "failed to initialize" in result.stderr
            try:
                notify.recv(256)
                raise AssertionError("failed startup announced READY")
            except socket.timeout:
                pass
        finally:
            blocker.close()
            notify.close()
        result = subprocess.run(smoke.vane_command(binary, str(path)),
            env={**os.environ, "NOTIFY_SOCKET": str(Path(directory) / "missing")},
            capture_output=True, text=True, timeout=3)
        assert result.returncode != 0 and "readiness notification" in result.stderr


def empty(server: smoke.UdpMarkerServer) -> None:
    try:
        observed = server.received.get(timeout=.08)
    except queue.Empty:
        return
    raise AssertionError(f"unexpected forwarding: {observed[:24].hex()}")


def send_burst(client: socket.socket, port: int, packets: list[bytes], gso: bool) -> None:
    target = ("127.0.0.1", port)
    if gso:
        assert len({len(packet) for packet in packets}) == 1
        try:
            client.sendmsg([b"".join(packets)],
                [(socket.IPPROTO_UDP, 103, struct.pack("H", len(packets[0])))], 0, target)
            return
        except OSError as error:
            if error.errno not in (22, 92, 95, 38):
                raise
    for packet in packets:
        client.sendto(packet, target)


def test_udp_reclassification(binary: str, gso: bool, same_target: bool) -> None:
    if not smoke.HAVE_CRYPTOGRAPHY:
        raise RuntimeError("maintenance regressions require Python cryptography")
    port = smoke.reserve_port(socket.SOCK_DGRAM)
    a = smoke.UdpMarkerServer(smoke.reserve_port(socket.SOCK_DGRAM), b"A")
    b = smoke.UdpMarkerServer(smoke.reserve_port(socket.SOCK_DGRAM), b"B")
    a.start(); b.start()
    selected = a if same_target else b
    targets = [{"location": f"127.0.0.1:{a.port}",
                "sni": ["a.test", "b.test"] if same_target else ["a.test"]},
               {"location": "drop", "sni": ["none", "any"]}]
    if not same_target:
        targets.append({"location": f"127.0.0.1:{b.port}", "sni": ["b.test"]})
    config = {"logging": {"level": "trace"}, "listeners": [{
        "transport": "udp", "address": f"127.0.0.1:{port}", "targets": targets,
    }]}
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)
    def initial(host: str, number: int, partial: bool = False) -> bytes:
        return smoke.make_quic_initial(host, 1, scid=bytes([number])*8,
            dcid=bytes([number + 32])*8, crypto_limit=20 if partial else None)
    def expect(server: smoke.UdpMarkerServer, payload: bytes):
        assert server.received.get(timeout=1) == payload
        peer = server.peers.get(timeout=1)
        assert client.recvfrom(65535)[0] == server.marker
        return peer
    try:
        with instance(binary, config, abstract=True):
            old = initial("a.test", 1)
            client.sendto(old, ("127.0.0.1", port))
            old_peer = expect(a, old)
            partial = initial("b.test", 2, True)
            client.sendto(partial, ("127.0.0.1", port))
            forbidden = initial("denied.test", 3)
            third_allowed = initial("a.test", 4)
            send_burst(client, port, [forbidden, third_allowed], gso)
            client.sendto(forbidden[:100], ("127.0.0.1", port))
            malformed = bytearray(forbidden)
            malformed[5] = 21  # Invalid DCID length must not enter a fast path.
            client.sendto(malformed, ("127.0.0.1", port))
            old_data = b"\x40" + b"O" * 1199
            client.sendto(old_data, ("127.0.0.1", port))
            assert expect(a, old_data) == old_peer
            empty(a); empty(b)

            completed = initial("b.test", 2)
            client.sendto(completed, ("127.0.0.1", port))
            peer = expect(selected, partial)
            assert expect(selected, completed) == peer
            if same_target:
                assert peer == old_peer
            # Old Initial replay must be discarded in every receive fast path.
            send_burst(client, port, [old, old], gso)
            current_data = b"\x40" + b"N" * 1199
            client.sendto(current_data, ("127.0.0.1", port))
            assert expect(selected, current_data) == peer
            empty(a); empty(b)
            # A denied new probe must leave the established target untouched.
            client.sendto(forbidden, ("127.0.0.1", port))
            client.sendto(current_data, ("127.0.0.1", port))
            assert expect(selected, current_data) == peer
            empty(a); empty(b)
            # Incomplete side probes time out without disturbing the old flow.
            client.sendto(initial("a.test", 5, True), ("127.0.0.1", port))
            time.sleep(2.1)  # One-second probe plus the bounded expiry scan.
            client.sendto(current_data, ("127.0.0.1", port))
            assert expect(selected, current_data) == peer
    finally:
        client.close(); a.close(); b.close()


def main() -> None:
    global USE_NOTIFY
    if len(sys.argv) != 2:
        raise SystemExit("usage: maintenance_regressions.py VANE_BINARY")
    binary = str(Path(sys.argv[1]).resolve())
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        probe.close()
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT):
            raise
        USE_NOTIFY = False
        print("SKIP live Unix readiness IPC: host restriction; protocol has a separate C unit test")
    test_readiness(binary)
    for gso, same_target in [(False, False), (True, False), (True, True)]:
        test_udp_reclassification(binary, gso, same_target)
    print("readiness and UDP maintenance regressions passed")


if __name__ == "__main__":
    main()
