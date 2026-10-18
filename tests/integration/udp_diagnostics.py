#!/usr/bin/env python3
"""Verify UDP trace/debug diagnostics with real NextQUIC Initial packets."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time

_RESERVED_PORTS: set[int] = set()

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


def vane_command(binary: str, *args: str) -> list[str]:
    """Run a native or emulated test instance on one allowed CPU."""
    runner = shlex.split(os.environ.get("VANE_TEST_RUNNER", ""))
    command = [*runner, binary, *args]
    taskset = shutil.which("taskset")
    if taskset is not None and hasattr(os, "sched_getaffinity"):
        cpus = sorted(os.sched_getaffinity(0))
        if cpus:
            return [taskset, "-c", str(cpus[0]), *command]
    return command


def reserve_udp_port() -> int:
    for _ in range(128):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        finally:
            sock.close()
        if port not in _RESERVED_PORTS:
            _RESERVED_PORTS.add(port)
            return port
    raise RuntimeError("could not reserve a unique UDP test port")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)

    public_port = reserve_udp_port()
    upstream_port = reserve_udp_port()
    ready = threading.Event()
    stop = threading.Event()

    def upstream() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", upstream_port))
        sock.settimeout(0.1)
        ready.set()
        try:
            while not stop.is_set():
                try:
                    _, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                sock.sendto(b"OK", peer)
        finally:
            sock.close()

    thread = threading.Thread(target=upstream, daemon=True)
    thread.start()
    assert ready.wait(timeout=2.0)

    config = {
        "logging": {"level": "trace"},
        "listeners": [{
            "address": f"[::]:{public_port}",
            "transport": "udp",
            "targets": [{
                "location": f"127.0.0.1:{upstream_port}",
                "sni": ["localhost"],
            }],
        }],
    }

    config_fd, config_path = tempfile.mkstemp(prefix="vane-diag-", suffix=".json")
    log_fd, log_path = tempfile.mkstemp(prefix="vane-diag-", suffix=".log")
    os.close(config_fd)
    os.close(log_fd)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle)

    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    with open(log_path, "w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            vane_command(binary, config_path), stdout=subprocess.DEVNULL,
            stderr=log_handle, text=True, env=env,
        )
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Vane exited during diagnostic startup")
            with open(log_path, "r", encoding="utf-8") as handle:
                if "UDP worker 0 started" in handle.read():
                    break
            time.sleep(0.03)
        else:
            raise RuntimeError("UDP worker did not start")

        with open(os.path.join(FIXTURE_DIR, "nextquic-v1-initial-1.bin"), "rb") as handle:
            packet1 = handle.read()
        with open(os.path.join(FIXTURE_DIR, "nextquic-v1-initial-2.bin"), "rb") as handle:
            packet2 = handle.read()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1.0)
        try:
            client.sendto(packet1, ("127.0.0.1", public_port))
            client.sendto(packet2, ("127.0.0.1", public_port))
            assert client.recvfrom(65535)[0] == b"OK"
            assert client.recvfrom(65535)[0] == b"OK"
        finally:
            client.close()

        time.sleep(0.1)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        stop.set()
        thread.join(timeout=1.0)

    with open(log_path, "r", encoding="utf-8") as handle:
        logs = handle.read()
    required = (
        "ingress peer=",
        "QUIC probe pending",
        "class=quic",
        "sni=localhost",
        "proxy_protocol=off",
        "activated client=",
        "first upstream response",
    )
    for marker in required:
        assert marker in logs, f"missing log marker {marker!r}:\n{logs}"

    os.unlink(config_path)
    os.unlink(log_path)
    print("UDP diagnostic logging test passed")


if __name__ == "__main__":
    main()
