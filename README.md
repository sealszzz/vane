# Vane

Vane forwards TCP TLS and UDP QUIC traffic on Linux. It selects an upstream by
the visible TLS Server Name Indication (SNI) and leaves TLS and QUIC termination
to that upstream. QUIC v1 and v2 are supported for SNI routing.

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

The installer verifies package checksums and architecture, validates the
configuration, and installs a systemd service. On upgrade it preserves a
valid configuration and rolls back if activation fails. The service reports
ready after every listener worker has started.

On a first installation, edit the example at `/etc/vane/vane.json` before
starting the service.

```sh
sudo /usr/local/bin/vane --check /etc/vane/vane.json
sudo systemctl restart vane
```

## Complete uninstall

Run the uninstaller from the extracted binary package or source tree.

```sh
sudo ./uninstall.sh
```

This stops and disables the service and removes Vane's binaries, unit,
documentation, and configuration directory including edited settings. It
also removes the dedicated system user and group created by the installer.

## Configuration

Each listener has a transport, a numeric IP socket address, and upstream
targets. The [example configuration](configs/vane.json) covers both TCP and
UDP on port 443. Validate edits before restarting the service.

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

## GitHub Actions

Open **Actions > Vane Build > Run workflow** after pushing the commit.

| Mode | Result |
|---|---|
| `build-only` | Build, test, and upload workflow artifacts |
| `publish` | Publish a new version from the default branch |
| `replace` | Replace the published assets for the current version from the default branch |

See [Release validation](BUILDING.md#release-validation) for the checks and
replacement procedure.

## Documentation

- [Configuration](docs/CONFIG.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Features and boundaries](docs/FEATURES.md)
- [Building from source](BUILDING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
