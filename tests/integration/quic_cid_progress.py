#!/usr/bin/env python3
"""Observed server Initial CID changes must preserve the existing UDP route."""
from pathlib import Path
import socket
import sys

import integration_smoke as smoke
import maintenance_regressions as maintenance


def with_leading_packet(initial, first_byte, dcid, scid):
    # The relay only needs the framing of the leading protected packet.
    ciphertext = bytes(24)
    header = bytes([first_byte]) + initial[1:5]
    header += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return header + smoke.encode_varint(len(ciphertext)) + ciphertext + initial


def run(binary, version, retry, *, negotiated_version=None, grease_bit=False,
        coalesced=False):
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
            cached_token = b"cached-token" if grease_bit else b""
            first = smoke.make_quic_initial("cid.test", version, dcid=dcid, scid=scid,
                                           grease_bit=grease_bit, token=cached_token)
            if coalesced:
                first = with_leading_packet(first, 0xd0 if version == 1 else 0xe0,
                                            dcid, scid)
            client.sendto(first, target)
            received, peer = backend.recvfrom(65535)
            assert received == first
            key_dcid = dcid
            if retry:
                # Valid Retry integrity tag (RFC 9001 / RFC 9369).
                wire_version = 1 if version == 1 else 0x6b3343cf
                header = bytes([0xf0 if version == 1 else 0xc0])
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
                # An observed Retry alias forwards the first fragment without
                # waiting for the rest of the same ClientHello.
                continuation = smoke.make_quic_initial("cid.test", version,
                    dcid=retry_cid, scid=scid, token=b"token", crypto_limit=16)
                client.sendto(continuation, target)
                assert backend.recvfrom(65535) == (continuation, peer)
            server_version = negotiated_version or version
            response = smoke.make_quic_initial("unused", server_version, dcid=scid,
                scid=server_cid, initial_dcid=key_dcid, server=True,
                crypto_frames=b"\x01")
            if coalesced:
                response = with_leading_packet(
                    response, 0xe0 if server_version == 1 else 0xf0, scid, server_cid)
            backend.sendto(response, peer)
            assert client.recvfrom(65535)[0] == response
            continuation = smoke.make_quic_initial("cid.test", server_version,
                dcid=server_cid, scid=scid, initial_dcid=key_dcid,
                packet_number=1, crypto_frames=b"\x02\x00\x00\x00\x00",
                token=b"token" if retry else cached_token)
            for gso in (False, True):
                maintenance.send_burst(client, public, [continuation, continuation], gso)
                for _ in range(2):
                    assert backend.recvfrom(65535) == (continuation, peer)
            # An unobserved DCID with the same client SCID is still a candidate,
            # and cannot bypass classification just because a server CID is known.
            denied = smoke.make_quic_initial("denied.test", server_version,
                dcid=b"Z" * 8, scid=scid)
            client.sendto(denied, target)
            client.sendto(continuation, target)
            assert backend.recvfrom(65535) == (continuation, peer)


def run_same_upstream(binary):
    public = smoke.reserve_port(socket.SOCK_DGRAM)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as backend, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        backend.bind(("127.0.0.1", 0))
        backend.settimeout(1)
        client.settimeout(1)
        location = f"127.0.0.1:{backend.getsockname()[1]}"
        config = {"listeners": [{
            "transport": "udp", "address": f"127.0.0.1:{public}",
            "targets": [{"location": location}, {"location": location, "sni": ["cid.test"]}],
        }]}
        target = ("127.0.0.1", public)
        with maintenance.instance(binary, config):
            datagram = b"udp before Initial"
            client.sendto(datagram, target)
            received, peer = backend.recvfrom(65535)
            assert received == datagram
            backend.sendto(b"reply", peer)
            assert client.recvfrom(65535)[0] == b"reply"
            initial = smoke.make_quic_initial("cid.test", 1)
            client.sendto(initial, target)
            assert backend.recvfrom(65535) == (initial, peer)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: quic_cid_progress.py VANE_BINARY")
    # Some validation hosts prohibit Unix datagram sockets.
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM):
            pass
    except PermissionError:
        maintenance.USE_NOTIFY = False
    binary = str(Path(sys.argv[1]).resolve())
    for version in (1, 2):
        for retry in (False, True):
            run(binary, version, retry)
        run(binary, version, False, grease_bit=True)
        run(binary, version, False, negotiated_version=3 - version)
        run(binary, version, False, coalesced=True)
    run_same_upstream(binary)
    print("QUIC CID progress passed (Retry, greasing, coalescing, v1/v2 switch, same upstream)")
