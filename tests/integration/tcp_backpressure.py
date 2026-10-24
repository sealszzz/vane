#!/usr/bin/env python3
"""Large transfers, delayed reads and FIN must progress without a new edge."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from tcp_half_close import reserve_port, vane_command, wait_started


def run(binary, proxy):
    public, upstream = reserve_port(), reserve_port()
    payload = bytes(range(256)) * 8192
    errors = []
    ready = threading.Event()
    def backend():
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", upstream))
                listener.listen()
                ready.set()
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(6)
                    time.sleep(0.1)
                    received = bytearray()
                    while True:
                        block = conn.recv(65536)
                        if not block:
                            break
                        received.extend(block)
                    if proxy:
                        assert received[:12] == b"\r\n\r\n\0\r\nQUIT\n"
                        header_len = 16 + int.from_bytes(received[14:16], "big")
                        del received[:header_len]
                    assert hashlib.sha256(received).digest() == hashlib.sha256(payload).digest()
                    conn.sendall(received)
                    conn.shutdown(socket.SHUT_WR)
        except BaseException as error:
            errors.append(error)
            ready.set()
    thread = threading.Thread(target=backend, daemon=True)
    thread.start()
    assert ready.wait(2)
    with tempfile.TemporaryDirectory(prefix="vane-backpressure-") as directory:
        config = Path(directory) / "vane.json"
        config.write_text(json.dumps({"logging": {"level": "error"}, "listeners": [{
            "transport": "tcp", "address": f"127.0.0.1:{public}",
            "targets": [{"location": f"127.0.0.1:{upstream}", "proxy_protocol": proxy}],
        }]}))
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(vane_command(binary, str(config)), stderr=log)
            try:
                wait_started(process)
                with socket.create_connection(("127.0.0.1", public), timeout=6) as client:
                    client.sendall(payload)
                    client.shutdown(socket.SHUT_WR)
                    time.sleep(0.1)
                    received = bytearray()
                    while True:
                        block = client.recv(65536)
                        if not block:
                            break
                        received.extend(block)
                    assert received == payload
                thread.join(2)
                assert not thread.is_alive()
                if errors:
                    raise errors[0]
            finally:
                process.terminate()
                process.wait(3)
                if process.returncode not in (0, -15):
                    log.seek(0)
                    raise RuntimeError(log.read().decode(errors="replace"))


if __name__ == "__main__":
    for proxy in (False, True):
        run(os.path.abspath(sys.argv[1]), proxy)
    print("TCP backpressure and FIN passed (plain and PROXY v2)")
