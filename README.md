# Vane

Vane is a Linux pass-through router for TCP TLS and UDP QUIC traffic. It
selects an upstream from the TLS Server Name Indication (SNI) without
terminating TLS or QUIC.

## Highlights

- TCP TLS and UDP QUIC listeners with exact, wildcard, `none`, `any`, fallback,
  and drop routes.
- QUIC v1 and v2 Initial parsing with bounded CRYPTO reassembly.
- Worker-owned epoll data paths with no per-flow threads or asynchronous
  runtime.
- UDP GRO/GSO support with automatic fallback when kernel offloads are
  unavailable.
- Connected UDP flows retain their upstream socket and source port while they
  remain in the flow table.
- Delayed QUIC Initial packets can repair a fallback flow, and a new QUIC
  connection reusing the same public tuple can be rerouted without restarting
  the process.
- Strict JSON validation without legacy aliases or runtime tuning fields.
- Optional TCP and UDP PROXY protocol v2 output.

Vane does not act as a TLS endpoint, QUIC endpoint, HTTP server, DNS resolver,
or Linux TPROXY listener.

## Supported platforms

Official builds target:

- Linux AMD64 with x86-64-v3 support
- Linux ARM64

## Install a binary package

For Linux AMD64-v3, extract the matching release package and run the
included installer as root (use `linux-arm64` in both names for ARM64):

```sh
VERSION="X.Y.Z"   # Replace X.Y.Z with the version shown on GitHub Releases.
PACKAGE="vane-${VERSION}-linux-amd64-v3"
tar -xJf "${PACKAGE}.tar.xz"
cd "$PACKAGE"
sudo ./install.sh
```

The installer verifies the package checksums and architecture, validates the
configuration before replacing installed files, installs a hardened systemd
service, and restores the previous installation if activation fails.
Activation waits for every listener worker to report ready before the upgrade
is committed.

On a first installation, the example configuration is installed but the service
is not started automatically. Edit `/etc/vane/vane.json`, then run:

```sh
sudo /usr/local/bin/vane --check /etc/vane/vane.json
sudo systemctl restart vane
```

Existing valid configurations are preserved during upgrades. The standalone
UDP offload diagnostic is not deployed, and a successful upgrade removes the
previously installed copy if present.

## Complete uninstall

Run the uninstaller from the extracted binary package (or source tree):

```sh
sudo ./uninstall.sh
```

This stops and disables the systemd service, removes the application binary,
legacy diagnostic binary, service unit, dedicated configuration directory
(including all edited settings), and its dedicated system user/group if they
match the installer-created identity. It also removes any files installed by
`cmake --install` under Vane's own shared-data and documentation directories.
The uninstaller does not remove historical entries from the *shared* systemd
journal or any copies of archives you've kept elsewhere.

## Configuration

A listener contains a transport, a numeric socket address, and a target set. DNS names are not accepted as listener or upstream addresses.

```json
{
  "logging": {
    "level": "info"
  },
  "listeners": [
    {
      "transport": "tcp",
      "address": "[::]:443",
      "targets": [
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
  ]
}
```

Validate a configuration without starting the service:

```sh
vane --check /etc/vane/vane.json
```

See [JSON configuration](docs/CONFIG.md) for the complete schema and routing
rules.

## Operation

```sh
systemctl status vane
journalctl -u vane -n 200 -o cat --no-pager
```

Available log levels are `error`, `warn`, `info`, `debug`, and `trace`.

The UDP GSO/GRO diagnostic tool is built for tests but is not installed with Vane.
To run it from a local development build:

```sh
./build/vane_udp_offload_probe
```

## GitHub Actions

The workflow is triggered manually from **Actions > Vane Build > Run workflow**.
Select `build-only` to compile, test, and upload temporary workflow artifacts,
or `publish` to perform the same checks and create a GitHub Release. A normal
`git push` does not trigger this workflow.

Published releases and their tags are immutable. After successfully publishing
a version, update `VERSION` and the changelog before publishing a different
build; rerunning `publish` with an existing release tag will be rejected.

## Documentation

- [Configuration](docs/CONFIG.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Features and boundaries](docs/FEATURES.md)
- [Building from source](BUILDING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
