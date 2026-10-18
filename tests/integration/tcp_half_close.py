#!/usr/bin/env python3
"""Regression test for TCP half-close correctness and epoll idle CPU use."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field


_RESERVED_PORTS: set[int] = set()


def reserve_port() -> int:
    for _ in range(128):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        finally:
            sock.close()
        if port not in _RESERVED_PORTS:
            _RESERVED_PORTS.add(port)
            return port
    raise RuntimeError("could not reserve a unique TCP test port")


def vane_command(binary: str, config: str) -> list[str]:
    runner = shlex.split(os.environ.get("VANE_TEST_RUNNER", ""))
    command = [*runner, binary, config]
    taskset = shutil.which("taskset")
    if taskset is not None and hasattr(os, "sched_getaffinity"):
        cpus = sorted(os.sched_getaffinity(0))
        if cpus:
            return [taskset, "-c", str(cpus[0]), *command]
    return command


def wait_started(process: subprocess.Popen[str]) -> None:
    # Do not probe the listener with a TCP connection: the test upstreams
    # intentionally accept exactly one connection and must observe the real
    # half-close case, not a readiness probe.
    deadline = time.monotonic() + 0.6
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=1)
            raise RuntimeError(f"Vane exited during startup:\n{stderr}")
        time.sleep(0.03)


def process_cpu_seconds(pid: int) -> Optional[float]:
    try:
        fields = open(f"/proc/{pid}/stat", "r", encoding="ascii").read().split()
    except FileNotFoundError:
        # Some nested PID namespaces expose a child PID to Python without a
        # matching entry in the mounted /proc. Functional half-close checks
        # still run there; ordinary Linux and CI environments retain the CPU
        # regression assertion below.
        return None
    ticks = int(fields[13]) + int(fields[14])
    return ticks / os.sysconf(os.sysconf_names["SC_CLK_TCK"])


def assert_idle_cpu(process: subprocess.Popen[str], duration: float = 1.2) -> None:
    start = process_cpu_seconds(process.pid)
    if start is None:
        assert process.poll() is None
        time.sleep(duration)
        assert process.poll() is None
        return
    time.sleep(duration)
    end = process_cpu_seconds(process.pid)
    assert end is not None
    used = end - start
    # A broken EPOLLRDHUP loop consumes roughly duration seconds on the pinned
    # CPU. Leave generous headroom for sanitizers and busy CI hosts.
    assert used < duration * 0.45, (used, duration)


@dataclass
class ClientFinServer:
    port: int
    ready: threading.Event = field(default_factory=threading.Event)
    got_eof: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        assert self.ready.wait(2.0)

    def _run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        self.ready.set()
        try:
            conn, _ = listener.accept()
            with conn:
                while conn.recv(65536):
                    pass
                self.got_eof.set()
                assert self.release.wait(4.0)
                conn.sendall(b"late-response")
        finally:
            listener.close()

    def close(self) -> None:
        self.release.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)


@dataclass
class UpstreamFinServer:
    port: int
    ready: threading.Event = field(default_factory=threading.Event)
    sent_fin: threading.Event = field(default_factory=threading.Event)
    received: bytes = b""
    thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        assert self.ready.wait(2.0)

    def _run(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen()
        self.ready.set()
        try:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"upstream-fin")
                conn.shutdown(socket.SHUT_WR)
                self.sent_fin.set()
                chunks = bytearray()
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    chunks += data
                self.received = bytes(chunks)
        finally:
            listener.close()

    def close(self) -> None:
        if self.thread is not None:
            self.thread.join(timeout=2.0)


def run_case(binary: str, mode: str) -> None:
    listen_port = reserve_port()
    upstream_port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="vane-half-close-") as directory:
        config = {
            "logging": {"level": "error"},
            "listeners": [{
                "transport": "tcp",
                "address": f"127.0.0.1:{listen_port}",
                "targets": [{"location": f"127.0.0.1:{upstream_port}"}],
            }],
        }
        config_path = os.path.join(directory, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        server = ClientFinServer(upstream_port) if mode == "client-fin" else UpstreamFinServer(upstream_port)
        server.start()
        process = subprocess.Popen(
            vane_command(binary, config_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_started(process)
            client = socket.create_connection(("127.0.0.1", listen_port), timeout=2.0)
            client.settimeout(3.0)
            if mode == "client-fin":
                client.sendall(b"request")
                client.shutdown(socket.SHUT_WR)
                assert server.got_eof.wait(2.0)
                assert_idle_cpu(process)
                server.release.set()
                assert client.recv(65536) == b"late-response"
                assert client.recv(65536) == b""
            else:
                assert server.sent_fin.wait(2.0)
                assert client.recv(65536) == b"upstream-fin"
                assert client.recv(65536) == b""
                assert_idle_cpu(process)
                client.sendall(b"after-fin")
                client.shutdown(socket.SHUT_WR)
            client.close()
            server.close()
            if mode == "upstream-fin":
                assert server.received == b"after-fin", server.received
        finally:
            process.terminate()
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
            server.close()
            if process.returncode not in (0, -15):
                stderr = process.stderr.read() if process.stderr is not None else ""
                raise RuntimeError(f"Vane exited with {process.returncode}:\n{stderr}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} /path/to/vane", file=sys.stderr)
        return 2
    run_case(sys.argv[1], "client-fin")
    run_case(sys.argv[1], "upstream-fin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
