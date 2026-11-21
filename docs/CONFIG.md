# JSON configuration

Vane uses strict JSON. It rejects duplicate keys, invalid UTF-8, embedded NUL,
excessive nesting, unknown fields, type errors, and overlapping listeners.
Use numeric IP socket addresses for listeners and upstreams.
IPv4-mapped IPv6 listener addresses are rejected; use IPv4 notation for those
listeners so aliases cannot bypass overlap validation.

```sh
vane --check /etc/vane/vane.json
```

## Built-in runtime policy

Worker counts, capacities, timeouts, and socket buffers are built in. See
[Architecture](ARCHITECTURE.md) for the operating limits.

## Listeners and targets

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

The required `listeners` array holds one or more listeners. Set `transport`
to `tcp` or `udp`, and each target `location` to a numeric IP and port or
`drop`. On a listener with SNI rules, Vane selects a target in the
following order.

| What the listener sees | Lookup order |
|---|---|
| ClientHello with SNI | Exact hostname, longest wildcard suffix, then `any` (also written `*`) |
| ClientHello without SNI | `none`, then `any` |
| Non-TLS TCP prefix or a short, undecided prefix when probing ends | Fallback |
| UDP on a new tuple without a recognized QUIC Initial | Fallback |

An SNI rule of `*.example.com` matches subdomains of `example.com`, including
nested subdomains. An omitted `sni` field defines the fallback. Traffic is
dropped when no applicable target exists or probing rejects a malformed
handshake. A listener configured with only a fallback uses that target
directly.

Each listener allows one fallback, one `none` rule, and one `any` rule.
`proxy_protocol` defaults to false and can be enabled on address targets.
UDP adds one PROXY v2 header per datagram. Enable it only when the upstream
expects that framing.

## Logging

The optional `logging.level` is `error`, `warn`, `info` (default), `debug`,
or `trace`. Use `debug` for route selection and upstream events, or `trace`
for packet handling and expiry details.
