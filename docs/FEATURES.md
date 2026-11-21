# Features and boundaries

| Traffic | Routing input |
|---|---|
| TCP TLS | SNI from the visible ClientHello, including one split across TLS records |
| QUIC v1 or v2 | SNI from the visible ClientHello reassembled from Initial packets |
| TLS or QUIC with ECH | SNI in the outer ClientHello, typically the ECH public name |
| UDP on a new tuple without a recognized Initial | Listener fallback |

ECH encrypts the inner ClientHello. Configure a route for the visible public
name to reach an upstream that can handle that ECH configuration. See
[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html#section-10.5).

TCP and UDP can share the same IP and port. Both support IPv4, IPv6, dual-stack
`[::]` listeners, and optional PROXY protocol v2. See [JSON
configuration](CONFIG.md) for route precedence and [Architecture](ARCHITECTURE.md)
for buffering, UDP flow retention, and offload handling.
