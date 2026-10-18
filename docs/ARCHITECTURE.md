# Architecture

## Threads and ownership

Each listener creates fixed `SO_REUSEPORT` pthread workers:

```text
worker threads = listener count x workers_per_listener
```

Each worker exclusively owns its listener file descriptor, epoll instance,
connection or flow slab, upstream sockets, and buffer pools. Routing tables are
built at startup and remain read-only. Packets never move between workers.

When NOTIFY_SOCKET is present, the main process sends READY=1 only after all
workers have initialized. The installed Type=notify service waits for that
notification; an initialization or notification failure aborts startup.

## TCP

```text
PROBING -> CONNECTING -> RELAYING -> HALF_CLOSED -> FREE
```

- Connections are accepted with `SOCK_NONBLOCK | SOCK_CLOEXEC`.
- The ClientHello prefix is stored directly in the client-to-upstream buffer.
- Nonblocking connect, epoll interest, reads, writes, half-close handling, and
  deadlines share one state machine.
- The epoll token contains a connection ID and generation so reused slots or file
  descriptors cannot match stale events.
- Steady-state relay storage is 16 KiB per direction. TLS probing may expand to
  the handshake limit, and the larger allocation is released after draining.
- Each endpoint caches its current interest mask; `EPOLL_CTL_MOD` is issued only
  when the mask changes.
- After EOF, the completed read direction is removed from `EPOLLRDHUP` interest
  while the other direction may continue forwarding.
- A client FIN received during a nonblocking upstream connect is propagated
  only after connect completion and after buffered client data drains.
- An inactive half-close is reclaimed after 120 seconds. Probe, connect, and
  half-close scans run at most once every 100 ms.
- Linux controls TCP receive and send socket buffers through autotuning.

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
affected upstream flow (or public worker socket) before individual-datagram
fallback. Downstream datagrams continue to use sendmmsg when GSO is disabled.
Partial batch sends advance only completed messages; the remaining batch is
retried to observe its actual error. `ENOBUFS` is treated as backpressure and is
not expanded into a retry burst.

Recoverable upstream receive errors do not imply an empty payload queue. The
worker continues to EAGAIN; after eight recoverable errors in one turn it
explicitly rearms the socket before yielding, preserving edge-triggered
progress without requiring another network packet.

There are no locks, queues, or cross-thread packet handoffs between these
modules. Release LTO may optimize across translation units.

## UDP flow lifecycle

The flow key is the public client address plus the original local destination
address. Every active flow owns one connected upstream UDP socket. The open
addressing hash table and fixed slab are separate. Deletion uses backward-shift
compaction, and epoll tokens contain a flow ID and generation.

```text
PENDING -> ACTIVE(unconfirmed) -> ACTIVE(confirmed) -> QUIESCENT
                 |                    |
                 +---- REPROBING <----+
```

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
- `QUIESCENT`: a confirmed flow passed the short idle threshold. Only the state
  changes; the socket remains open and connected.
- Traffic in either direction refreshes `last_activity_ms`. A quiescent flow
  resumes on the same file descriptor.
- QUIC version plus both connection IDs identify the active Initial context.
  A server Retry is observed on the upstream path, and only its Source
  Connection ID is accepted as the next client Initial destination ID. An
  arbitrary DCID change with a reused client SCID is therefore not mistaken for
  a Retry continuation.
- If reprobe selects the current target, the connected upstream socket and
  source port are retained. If it selects a different target, Vane opens,
  configures, connects, and registers the replacement socket before closing the
  old one. A new epoll generation rejects stale events from the old socket.
- Malformed, incomplete, timed-out, denied, unroutable, or capacity-limited
  reprobes are discarded and the established flow remains active. Candidate
  packets are never sent to the old target before classification.
- The receive path applies the same decision before ordinary forwarding,
  recvmmsg rebatching, and UDP GRO aggregate forwarding.
- Each flow remembers up to four replaced Initial identities for two minutes,
  including an observed Retry continuation when applicable. Recent old Initial
  packets are discarded before they can replace the current route. This bounded
  history is not general anti-replay protection or multi-connection CID routing.
- A confirmed flow has a rolling 24-hour hard-idle limit, but it may be removed
  earlier by capacity-pressure reclamation, shutdown, or a non-preservable
  socket error. A denied side-probe candidate never removes the established
  flow.

## Two-tier capacity

The global UDP base capacity is 4096 and is sharded across UDP listener workers.
Every worker reserves metadata for twice its base share at startup. Runtime
capacity switches only between:

```text
base limit <-> burst limit (base x 2)
```

Built-in watermarks are:

```text
high = 80%
low  = 65%
```

At the current tier's high watermark, Vane collects eligible expired or idle
candidates, orders them from least recently active to most recently active, and
deletes in a batch down to that tier's low watermark when possible. While using
the base limit, if usage remains above the base-tier low watermark after this
reclamation pass, the logical admission limit switches to the burst tier. It
returns to the base tier after usage falls to the base-tier low watermark.

Returning to the base tier changes only the logical admission limit. Existing
flows are not moved, closed, or reconnected. At a full burst tier with no
reclaimable flow, new flows are rejected and established paths are preserved.

## Data paths

Public admission is level-triggered and processed in a bounded quantum per
event-loop turn. Established upstream sockets remain edge-triggered and drain to
`EAGAIN`; the admission boundary yields fairly under connection or packet storms
without adding a rate limiter to established relay traffic.

Public to upstream:

```text
recvmmsg
 -> PKTINFO + TOS/TCLASS + UDP_GRO
 -> flow lookup / QUIC probe
 -> connected upstream socket
 -> UDP_SEGMENT or per-datagram fallback
```

Upstream to public:

```text
upstream EPOLLIN
 -> recvmsg + UDP_GRO
 -> downstream batch
 -> sendmmsg
 -> optional UDP_SEGMENT
```

## Protocol boundary

Vane passively parses TLS ClientHello, QUIC v1/v2 Initial packets, CRYPTO
reassembly, SNI routing, and PROXY v2. It does not send QUIC acknowledgements,
perform congestion control, or maintain a complete QUIC endpoint.

Protection keys derived from a QUIC Initial DCID, packet-number reconstruction
state, and decrypted Initial payloads are retained only for the lifetime of one
bounded pending probe. Each newly received Initial datagram is decrypted once;
subsequent datagrams reuse the same protection and packet-number state, while
CRYPTO frames are reassembled from retained decrypted payloads without re-running
cryptography over the already buffered datagrams. Client Initial
datagrams smaller than 1200 bytes are rejected before key derivation.

An in-memory flow and its upstream source port disappear after process restart,
flow replacement, a confirmed-flow hard-idle deletion, capacity-pressure
eviction, or a non-preservable socket error. A stateless QUIC short header cannot
be reliably distinguished from arbitrary UDP payload without flow history, so
the listener fallback rule applies when history is unavailable.
