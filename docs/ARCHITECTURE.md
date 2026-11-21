# Architecture

## Threads and ownership

Each listener uses a fixed group of `SO_REUSEPORT` workers. The group size
depends on CPU affinity, listener count, and built-in capacity. Each worker
owns its sockets, epoll instance, connection or flow slots, and buffers.
Workers share read-only routing tables built at startup.

The installed systemd service uses `Type=notify`. The main process sends
`READY=1` after all workers initialize. An initialization or notification
failure aborts startup.

## TCP

The TCP capacity of 4096 connections is shared across TCP listener workers.
Connections progress through probing, nonblocking upstream connect, and
relay. An epoll token combines the slot ID and generation to reject stale
events after reuse.

- The probe reads into the client-to-upstream buffer. Relay storage is 16 KiB
  per direction. The larger TLS probe allocation is released after draining.
- After a read or upstream connect completes, buffered relay data is sent
  in the same callback. `EPOLLOUT` stays armed for unsent bytes. Draining a
  full read buffer forces an edge-triggered readiness recheck even if the
  interest mask stayed the same.
- EOF removes read interest from that direction. Vane relays the FIN after
  upstream connect and after queued bytes drain. The reverse direction can
  remain active.
- The 120-second idle timer starts at the first EOF and refreshes on another
  EOF or successful I/O. Deadline scans are spaced at least 100 ms apart.
- Linux autotunes the TCP socket buffers.

## UDP modules

- `udp_worker.c`: initialization, shutdown, and the epoll loop.
- `udp_flow.c`: flow slab, hash table, capacity, upstream socket lifecycle, and
  timeouts.
- `udp_probe.c`: bounded QUIC Initial buffering, parsing, and routing.
- `udp_receive.c`: public and upstream receive paths, GRO splitting, and
  same-flow rebatching.
- `udp_send.c`: upstream GSO, downstream `sendmmsg`, PROXY v2, and per-datagram
  fallback.

An `EINVAL`, `EMSGSIZE`, or unsupported-offload result disables GSO on the
affected upstream flow or public worker socket. Vane sends the unsent portion
as individual datagrams, including any short tail. UDP PROXY v2 adds one
header per original datagram. Downstream still uses `sendmmsg`, advancing by
the count of completed messages before retrying the remainder. Backpressure
such as `ENOBUFS` stops that send attempt.

Recoverable upstream receive errors do not imply an empty payload queue. The
worker continues receiving within the turn budget; after eight recoverable
errors, 64 successful receive results, or 1 MiB of aggregate payload in one
turn it explicitly rearms the socket before yielding. The byte budget can
overshoot by at most one receive buffer. GRO results count as one result, with
all their original datagrams preserved. This bounds hot-flow occupancy while
preserving edge-triggered progress without another network packet.

There are no locks, queues, or cross-thread packet handoffs between these
modules. Release LTO may optimize across translation units.

## UDP flow lifecycle

The flow key is the public client address plus the original local destination
address. Every active flow owns one connected upstream UDP socket. The open
addressing hash table and fixed slab are separate. Deletion uses backward-shift
compaction, and epoll tokens contain a flow ID and generation.

- `PENDING`: waits for bounded QUIC Initial parsing before an upstream socket
  exists.
- `ACTIVE(unconfirmed)`: packets were forwarded, but no upstream response has
  arrived; a short idle timeout applies.
- `ACTIVE(confirmed)`: the upstream path has responded.
- `REPROBING`: a complete-looking Initial for a different QUIC connection was
  observed on an existing public tuple. The old upstream socket remains open;
  only matching candidate long-header packets are buffered while established
  traffic continues on the old path. Other new Initial candidates are dropped
  until the current bounded side probe completes or is cancelled.
- `QUIESCENT`: a confirmed flow has been idle for three minutes. Traffic in
  either direction refreshes activity. A quiescent flow resumes on the same
  socket and source port while it remains in the table.
- QUIC version plus both connection IDs identify the active Initial context.
  The first server Retry and the first server Initial are observed on the
  connected upstream path. Their Source Connection IDs are accepted as client
  Initial destination IDs with the original client SCID. The Retry alias
  requires the original version; the Initial alias uses the observed version,
  including a compatible v1/v2 switch. Both aliases remain valid for reordering
  and later conflicting observations are ignored. An unobserved DCID still
  requires a side probe. These observations are used only for routing.
- If reprobe selects the same upstream address and PROXY v2 setting, the
  connected socket, source port, and confirmation state are retained. If it
  selects a different upstream or framing mode, Vane opens,
  configures, connects, and registers the replacement socket before closing the
  old one. A new epoll generation rejects stale events from the old socket.
- Malformed, incomplete, timed-out, denied, unroutable, or capacity-limited
  reprobes are discarded and the established flow remains active. Candidate
  packets are never sent to the old target before classification.
- The receive path applies the same decision before ordinary forwarding,
  recvmmsg rebatching, and UDP GRO aggregate forwarding.
- Each flow remembers up to four replaced Initial identities for two minutes,
  including observed Retry and server Initial continuations when applicable.
  The four-entry bound is shared by all aliases. Recent old Initial
  packets are discarded before they can replace the current route. This bounded
  history is not general anti-replay protection or multi-connection CID routing.
- A confirmed flow has a rolling 24-hour hard-idle limit, but it may be removed
  earlier by capacity-pressure reclamation, shutdown, or a non-preservable
  socket error. A denied side-probe candidate never removes the established
  flow.

## Two-tier capacity

The global UDP base capacity is 4096 and is sharded across UDP listener workers.
Every worker reserves metadata for twice its base share at startup, for a
global burst capacity of 8192. Both tiers use an 80% high watermark and a 65%
low watermark.

At the current tier's high watermark, Vane collects eligible expired or idle
candidates, orders them from least recently active to most recently active, and
deletes in a batch down to that tier's low watermark when possible. While using
the base limit, if usage remains above the base-tier low watermark after this
reclamation pass, the logical admission limit switches to the burst tier. It
returns to the base tier after usage falls to the base-tier low watermark.

Returning to the base tier lowers the admission limit and preserves existing
flows. A full burst tier rejects new flows when none can be reclaimed.

## Data paths

Public listeners use level-triggered epoll so they can yield after bounded
work. Established TCP and upstream UDP sockets use edge-triggered epoll.

| UDP direction | Receive | Forward |
|---|---|---|
| Public to upstream | `recvmmsg` collects payload, destination IP, traffic class, and GRO metadata | Look up the flow, probe when needed, and send on the connected UDP socket |
| Upstream to public | `recvmsg` reads into a downstream batch slot | `sendmmsg` uses the original public IP as the source and preserves traffic class |

## Protocol boundary

Vane reads TLS ClientHello directly from TCP or reassembles it from QUIC v1
and v2 Initial CRYPTO frames. The selected upstream handles the handshake and
transport state.

Protection keys derived from a QUIC Initial DCID, packet-number reconstruction
state, and decrypted Initial payloads are retained only for the lifetime of one
bounded pending probe. Each newly received Initial datagram is decrypted once;
subsequent datagrams reuse the same protection and packet-number state, while
CRYPTO frames are extracted only from newly decrypted payloads. Their indexed
views refer to the retained payloads. Each feed sorts the known frames and
checks overlaps while reusing the bounded buffer for the contiguous prefix.
Client Initial datagrams smaller than 1200 bytes are rejected before key
derivation.

An in-memory flow and its upstream source port disappear after process restart,
flow replacement, a confirmed-flow hard-idle deletion, capacity-pressure
eviction, or a non-preservable socket error. A stateless QUIC short header cannot
be reliably distinguished from arbitrary UDP payload without flow history, so
the listener fallback rule applies when history is unavailable.
