#!/usr/bin/env python3
"""Observed server Initial CID changes must preserve the existing UDP route."""
from pathlib import Path
import socket
import sys

import integration_smoke as smoke
import maintenance_regressions as maintenance


def run(binary, version, retry):
    public = smoke.reserve_port(socket.SOCK_DGRAM)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as backend, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        backend.bind(("127.0.0.1", 0))
        backend.settimeout(1)
        client.settimeout(1)
        config = {"logging": {"level": "info"}, "listeners": [{
            "transport": "udp", "address": f"127.0.0.1:{public}",
            "targets": [{"location": f"127.0.0.1:{backend.getsockname()[1]}",
                         "sni": ["cid.test"]},
                        {"location": "drop", "sni": ["none", "any"]}],
        }]}
        dcid, scid, retry_cid, server_cid = (bytes([i]) * 8 for i in range(1, 5))
        target = ("127.0.0.1", public)
        with maintenance.instance(binary, config):
            first = smoke.make_quic_initial("cid.test", version, dcid=dcid, scid=scid)
            client.sendto(first, target)
            received, peer = backend.recvfrom(65535)
            assert received == first
            key_dcid = dcid
            if retry:
                # Valid Retry integrity tag (RFC 9001 / RFC 9369).
                wire_version = 1 if version == 1 else 0x6b3343cf
                header = bytes([0xf0 if version == 1 else 0xe0])
                header += wire_version.to_bytes(4, "big")
                header += bytes([len(scid)]) + scid + bytes([len(retry_cid)]) + retry_cid
                header += b"token"
                key = bytes.fromhex("be0c690b9f66575a1d766b54e368c84e" if version == 1
                                    else "8fb4b01b56ac48e260fbcbcead7ccc92")
                nonce = bytes.fromhex("461599d35d632bf2239825bb" if version == 1
                                      else "d86969bc2d7c6d9990efb04a")
                pseudo = bytes([len(dcid)]) + dcid + header
                response = header + smoke.AESGCM(key).encrypt(nonce, b"", pseudo)
                backend.sendto(response, peer)
                assert client.recvfrom(65535)[0] == response
                key_dcid = retry_cid
                continuation = smoke.make_quic_initial("cid.test", version,
                    dcid=retry_cid, scid=scid, token=b"token")
                client.sendto(continuation, target)
                assert backend.recvfrom(65535) == (continuation, peer)
            response = smoke.make_quic_initial("unused", version, dcid=scid,
                scid=server_cid, initial_dcid=key_dcid, server=True,
                crypto_frames=b"\x01")
            backend.sendto(response, peer)
            assert client.recvfrom(65535)[0] == response
            continuation = smoke.make_quic_initial("cid.test", version,
                dcid=server_cid, scid=scid, initial_dcid=key_dcid,
                packet_number=1, crypto_frames=b"\x02\x00\x00\x00\x00",
                token=b"token" if retry else b"")
            for gso in (False, True):
                maintenance.send_burst(client, public, [continuation, continuation], gso)
                for _ in range(2):
                    assert backend.recvfrom(65535) == (continuation, peer)
            # An unobserved DCID with the same client SCID is still a candidate,
            # and cannot bypass classification just because a server CID is known.
            denied = smoke.make_quic_initial("denied.test", version,
                dcid=b"Z" * 8, scid=scid)
            client.sendto(denied, target)
            client.sendto(continuation, target)
            assert backend.recvfrom(65535) == (continuation, peer)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: quic_cid_progress.py VANE_BINARY")
    # Some validation hosts prohibit Unix datagram sockets.
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM):
            pass
    except PermissionError:
        maintenance.USE_NOTIFY = False
    for version in (1, 2):
        for retry in (False, True):
            run(str(Path(sys.argv[1]).resolve()), version, retry)
    print("QUIC server Initial CID progress passed (v1/v2, Retry, GRO/rebatch)")
