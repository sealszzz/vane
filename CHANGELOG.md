# Changelog

## Current release

- Preserve TCP ET read progress when a full probe buffer transitions to
  upstream connect, before PROXY headroom changes the logical buffer limit.
- Enforce the logical TCP read limit even when an earlier probe allocation
  is larger, preserving bounded relay work and buffer accounting.
- Track the first observed server Initial SCID as well as the first Retry
  SCID, preserving legitimate QUIC v1/v2 Initial continuations on the same
  upstream socket. Retire both aliases when a new connection takes over.
- Ignore later conflicting server Initial/Retry CID updates; arbitrary
  unobserved client DCID changes still require classification.
- Avoid redundant flow hashing for adjacent equal-key UDP datagrams during
  worker-local rebatching.
- Add no-new-write TCP probe-transition tests and process-level QUIC CID
  continuation tests, including Retry and GRO/rebatch paths.

## Previous maintenance release

- Flush TCP relay data in the current readiness callback; request EPOLLOUT only
  for queued data, and recheck ET read readiness after draining a full buffer.
- Share the relay flushing and half-close transition path between endpoints.
- Bound each upstream UDP receive turn to 64 receive results or 1 MiB and rearm
  ET readiness before yielding, preserving progress without another packet.
- Extract only new QUIC CRYPTO frames during a pending probe and reuse its
  contiguous assembly buffer; sparse gaps do not enlarge that buffer.
- Validate contiguous overlapping CRYPTO frames before accepting ClientHello.
- Allocate cross-record TLS assembly only after complete record payloads cover
  the declared handshake, avoiding repeated allocations on partial input.
- Add fragmentation, conflicting overlap, ET quantum, and large TCP backpressure
  regressions, including stripped release and cross-architecture packaging gates.
- Keep the configuration schema, routing policy, capacity tiers, UDP PROXY v2,
  installer, uninstaller, and immutable release workflow unchanged.

## Previous maintenance release

- Fixed installation rollback so failures before old files are backed up never
  remove the previous installation; incomplete restores retain their backups.
- Announce systemd readiness only after every listener worker initializes, and
  wait for that notification before committing an activated upgrade.
- Drop unrelated new Initial candidates while a UDP side probe is pending.
- Keep four retired QUIC Initial identities for up to two minutes per flow so
  recent delayed handshakes cannot revert a completed target switch.
- Continue draining UDP responses after recoverable receive errors, with a
  bounded error budget and explicit epoll rearming when yielding.
- Preserve ordinary sendmmsg batching after GSO compatibility fallback, including
  short tail segments, partial sends, and backpressure handling.
- Reject IPv4-mapped IPv6 listener notation instead of accepting overlapping
  aliases of an IPv4 listener.
- Added targeted rollback, readiness, reclassification, receive-error, and
  downstream batching regressions.

## Previous maintenance

- Made published releases immutable: publishing is restricted to the default
  branch, existing tags may only be reused at the same source commit, and an
  existing GitHub release is never edited or overwritten.
- Removed the UDP integration-test startup race by probing the complete UDP
  forwarding path before running assertions.
- Added the project MIT license, third-party notices, exact dependency revision
  manifests, and upstream license files to release packages.
- Extended release consistency and package verification gates to enforce the
  new publication and licensing invariants.

## Previous release

- Kept UDP upstream error history across successful local `sendmsg` calls;
  only a real upstream response or a deliberate upstream replacement clears the
  error state, preventing asynchronous `ECONNREFUSED` storms from defeating
  warning suppression when a previously healthy UDP backend restarts.
- Added client, target, and local source addresses to unconfirmed UDP upstream
  failure logs so a refused backend can be distinguished from SNI routing errors.
- Bounded public TCP accept and UDP receive work per event-loop turn while
  keeping established relay sockets edge-triggered, preventing admission storms
  from monopolizing a worker.
- Switched only public admission sockets to level-triggered epoll so bounded
  work can safely yield without losing an edge.
- Made QUIC Initial probing incremental: each newly buffered datagram is
  decrypted once while Initial protection, packet-number state, and decrypted
  payloads live for the bounded probe lifetime; reassembly uses those retained
  plaintext payloads without repeating cryptography.
- Rejected RFC-invalid sub-1200-byte client Initial datagrams before expensive
  QUIC cryptographic processing.
- Changed the installed systemd service to `Restart=always` so an external
  SIGTERM from a resource guard is followed by automatic service recovery.
- Fixed persistent UDP fallback misclassification when a non-Initial datagram
  arrived before a delayed or reordered QUIC Initial.
- Added a reversible active-flow QUIC reprobe state that keeps the established
  upstream socket and forwards unrelated old-connection traffic while matching
  candidate long-header packets are classified.
- Tracked exact QUIC Initial connection identity and observed server Retry
  packets so legitimate Retry continuations stay on the established path
  without treating arbitrary same-SCID connections as equivalent.
- Swapped upstream sockets only after the replacement socket was fully opened,
  connected, and registered with epoll; stale events are rejected by a new
  generation token.
- Covered ordinary receive, recvmmsg rebatching, and UDP GRO aggregate paths so
  no active-flow fast path can bypass reclassification.
- Preserved the old flow after malformed, incomplete, timed-out, denied,
  unroutable, or resource-limited reprobes instead of letting untrusted packets
  tear it down.
- Added unit and process-level regressions for fallback recovery, same-tuple SNI
  changes, denied and malformed Initial rollback, and QUIC connection identity
  handling.

## Earlier release

- Preserved the worker-owned epoll architecture and wire behavior.
- Deferred client FIN propagation until a nonblocking upstream TCP connect had
  completed.
- Disabled UDP GSO after path or kernel compatibility failures instead of
  retrying the same failing offload on every packet batch.
- Treated UDP `ENOBUFS` as backpressure without an unnecessary per-datagram
  retry pass.
- Reused QUIC Initial protection keys across datagrams in one probe.
- Removed the same-version release replacement path and the build-time
  pkg-config dependency.
- Added focused UDP GSO fallback tests.

## Initial release

- Added pass-through TCP TLS and UDP QUIC SNI routing for Linux.
- Added exact, wildcard, `none`, `any`, fallback, and drop routes.
- Added strict JSON configuration validation and optional PROXY protocol v2.
- Added QUIC v1/v2 Initial parsing with bounded CRYPTO reassembly.
- Added worker-owned epoll data paths, UDP GRO/GSO, and bounded flow capacity.
- Added connected UDP flow preservation across short idle periods.
- Added correct bidirectional TCP half-close handling and inactive half-close
  cleanup.
- Added AMD64 x86-64-v3 and ARM64 release builds with static AWS-LC and json-c.
- Added package checksum verification, embedded source archives, and a hardened
  systemd installer with rollback support.
