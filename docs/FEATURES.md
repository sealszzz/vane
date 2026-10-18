# Features and boundaries

| Behavior | Implementation |
|---|---|
| TCP and UDP on the same IP and port | Separate transport sockets; `SO_REUSEPORT` shards each transport across workers |
| IPv4, IPv6, and dual-stack `[::]` | Supported |
| Exact TLS SNI | Sorted binary search |
| Wildcard SNI | Longest matching suffix first |
| `none`, `any`, fallback, and `drop` | Supported |
| TCP and UDP PROXY v2 | Supported, disabled by default |
| ClientHello spanning TLS records | Bounded reassembly by declared length |
| QUIC v1/v2 Initial | Multi-datagram CRYPTO reassembly |
| Malformed TLS or QUIC | Strict rejection |
| UDP GRO and GSO | Bidirectional paths, short tail segments, persistent compatibility fallback, and bounded backpressure work |
| UDP idle resume | Same connected file descriptor and source port |
| UDP active-flow reclassification | Delayed Initial recovery, same-tuple new connection detection, reversible bounded reprobe, and atomic target switch |
| UDP dynamic capacity | Base tier and two-times burst tier, 80/65 watermarks |
| UDP long-term cleanup | Confirmed-flow 24-hour hard-idle limit with earlier bounded cleanup rules |
| PKTINFO, TCLASS, and ECN | Preserved for IPv4 and IPv6 |
| TCP half-close | Unified state machine, no RDHUP retrigger, 120-second idle cleanup |
| Configuration | Strict JSON without compatibility aliases |

Vane intentionally does not use an asynchronous runtime, per-flow tasks,
message channels, blocking pools, asynchronous semaphores, cross-worker packet
queues, or a separate cross-worker tuple-affinity cache. Each UDP worker still
maintains its own bounded tuple-to-flow table. Vane is not a QUIC endpoint and
does not implement congestion control or connection migration.
