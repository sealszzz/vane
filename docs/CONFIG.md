# JSON configuration

Vane uses strict JSON. It rejects duplicate keys, invalid UTF-8, embedded NUL,
excessive nesting, unknown fields, type errors, and overlapping listeners.
Addresses must be numeric IP socket addresses; DNS resolution is not performed.
IPv4-mapped IPv6 listener addresses are rejected; use IPv4 notation for those
listeners so aliases cannot bypass overlap validation.

Only the current schema is accepted. Legacy fields, aliases, and silent
migration are intentionally unsupported.

```sh
vane --check /etc/vane/vane.json
```

## Built-in runtime policy

JSON does not expose a `runtime` object. Worker counts, TCP and UDP capacities,
timeouts, socket buffers, batch sizes, and probe limits are built into the
program. A `runtime` root field is rejected.

Current policy:

- worker counts are derived from CPU affinity or cpuset, listener count, and
  built-in capacity;
- global TCP connection capacity is 4096, steady-state relay storage is 16 KiB
  per direction, and an inactive half-close is reclaimed after 120 seconds;
- TCP socket buffers use Linux autotuning;
- UDP flow base capacity is 4096 and burst capacity is 8192;
- a confirmed UDP flow becomes eligible for capacity-pressure reclamation after
  three minutes idle, while retaining its socket and source port until removal;
- a confirmed flow has a rolling 24-hour hard-idle limit, but bounded cleanup
  rules may remove it earlier;
- pending probes and unconfirmed flows use short timeouts;
- capacity management uses built-in 80 percent and 65 percent watermarks.

These values are implementation policy, not part of the public configuration
protocol.

## Listeners and targets

Recommended field order:

- listener: `transport`, `address`, `targets`
- normal target: `location`, `sni`, `proxy_protocol`
- fallback target: `location`, `proxy_protocol`
- drop target: `location`, `sni`

```json
{
  "transport": "tcp",
  "address": "[::]:443",
  "targets": [
    {
      "location": "drop",
      "sni": ["none", "any"]
    },
    {
      "location": "[::1]:9001",
      "sni": ["example.com", "*.example.net"],
      "proxy_protocol": false
    },
    {
      "location": "[::1]:9009",
      "proxy_protocol": false
    }
  ]
}
```

- `transport`: `tcp` or `udp`.
- `location`: numeric IP and port, or `drop`.
- omitted `sni`: fallback target.
- exact match: `example.com`.
- wildcard match: `*.example.com`; the longest suffix wins.
- `none`: a parsed TLS/QUIC ClientHello has no SNI.
- `any` or `*`: a parsed ClientHello with an SNI that did not match an exact or
  wildcard rule; also used for a parsed ClientHello without SNI if no `none`
  target exists.
- omitted or false `proxy_protocol`: disabled; only true enables it.

For a successfully parsed ClientHello, route precedence is exact SNI, longest
matching wildcard, then `any`; a missing SNI uses `none` first and `any` if
`none` is absent. The **fallback** (a target with no `sni` field) is separate:
it handles traffic identified as non-TLS on a TCP listener or non-QUIC on a UDP
listener, as well as certain incomplete TCP prefixes when probing ends.
Malformed protocol handshakes are rejected rather than routed to fallback.

A fallback with a numeric upstream address can therefore forward non-TLS or
non-QUIC traffic even if `none` and `any` both point to `drop`. To discard
unmatched non-protocol traffic instead, use a fallback with `"location": "drop"`
or omit the fallback target.

Each listener may contain at most one fallback target, one `none` target, and one
`any` target. A drop target cannot enable PROXY protocol. UDP PROXY v2 repeats
the header for every logical datagram, so it should remain disabled for ordinary
QUIC endpoints.

## Logging

- `debug`: flow classification, SNI, target, upstream, first response, capacity
  transitions, and important fallbacks.
- `trace`: individual datagrams, GRO segments, pending probes, GSO rebatching,
  and expiration details.
