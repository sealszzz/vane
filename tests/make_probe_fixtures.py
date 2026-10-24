#!/usr/bin/env python3
"""Regenerate bounded CRYPTO reassembly fixtures (requires cryptography)."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / "integration"))
from integration_smoke import encode_varint, make_quic_initial, make_tls_handshake

root = Path(__file__).parent / "fixtures"
def frame(offset, data):
    return b"\x06" + encode_varint(offset) + encode_varint(len(data)) + data
hello = make_tls_handshake("localhost")
for conflict in (False, True):
    overlap = bytearray(hello)
    if conflict:
        overlap[-1] ^= 1
    payload = frame(0, hello) + frame(0, overlap)
    name = "crypto-overlap-conflict.bin" if conflict else "crypto-overlap-valid.bin"
    (root / name).write_bytes(make_quic_initial("localhost", 1, crypto_frames=payload))
hello = make_tls_handshake("localhost", padding_bytes=4000)
chunk = (len(hello) + 7) // 8
for i in range(8):
    start, end = i * chunk, min((i + 1) * chunk, len(hello))
    payload = b"".join(frame(j, hello[j:min(j + 16, end)]) for j in range(start, end, 16))
    (root / f"crypto-fragment-{i}.bin").write_bytes(make_quic_initial(
        "localhost", 1, crypto_frames=payload, packet_number=i))
