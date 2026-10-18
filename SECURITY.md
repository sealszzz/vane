# Security

Vane parses untrusted TCP TLS ClientHello and UDP QUIC Initial traffic before
selecting an upstream. Treat parser correctness and length validation as security
boundaries.

## Runtime isolation

The supplied systemd unit runs as the unprivileged `vane` account. It receives
only `CAP_NET_BIND_SERVICE`, which is required for ports below 1024. The unit also
uses a read-only system view, private temporary/devices namespaces, restricted
address families and other systemd hardening controls.
AF_UNIX is allowed for the local systemd readiness notification. The process
does not announce readiness until all listener workers have initialized.

The configuration is installed as `root:vane` mode `0640`. Vane does not need
write access to its binary, configuration or system directories.

## Reporting

Do not publish packet captures, private SNI routing tables, internal addresses or
production configuration when reporting a defect. Provide a minimized reproducer
and the output of `vane --version` (and the development-only UDP offload probe, if available).
