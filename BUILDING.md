# Building from source

## Requirements

A development build requires:

- Linux
- CMake 3.28 or newer
- Ninja
- a C17 compiler
- OpenSSL-compatible crypto development files
- json-c development files
- Python 3 and its cryptography package for integration tests

Vane locates json-c directly through its headers and library; pkg-config is
not required.

## Development build

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DVANE_SANITIZE=ON \
  -DVANE_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Set `CC=gcc` or `CC=clang` before configuration to select a compiler.

## Release build

The release scripts build AWS-LC and json-c statically and then build Vane for
one of the supported targets:

```sh
./scripts/build-release.sh linux-amd64-v3
./scripts/build-release.sh linux-arm64
```

The ARM64 target requires an AArch64 cross compiler, sysroot, binutils, and
qemu-user. Native target tests run during the build. Cross-compiled unit tests
run under QEMU, and the routing, diagnostics, half-close, and maintenance
process-level integration tests run under QEMU after stripping. Native packages
also exercise staged installer rollback without changing the host installation.

Live readiness IPC tests require Unix datagram sockets. Restricted test hosts
skip only that live IPC subcase; the C readiness unit test still validates
notification encoding, abstract addresses, and send failures. UDP maintenance
regressions continue to run on those hosts.

The release workflow resolves stable dependency tags and their exact commits
once. Each architecture then clones the same tags and rejects a changed or
mismatched commit:

```sh
./scripts/resolve-latest-dependencies.sh
```

Each binary package records those resolved tags and commits in `DEPENDENCIES`.
The build also copies the exact AWS-LC and json-c license files from the
resolved source trees into `third_party/licenses/` in the package.

Exact dependency revisions can also be supplied manually. Replace the
example tags and quoted commit placeholders with actual release tags and their
40-character hexadecimal Git commit IDs:

```sh
AWSLC_REF=vX.Y.Z \
AWSLC_EXPECTED_COMMIT="REPLACE_WITH_AWSLC_40_HEX_COMMIT" \
JSONC_REF=json-c-X.Y-YYYYMMDD \
JSONC_EXPECTED_COMMIT="REPLACE_WITH_JSONC_40_HEX_COMMIT" \
./scripts/build-release.sh linux-amd64-v3
```

The UDP offload diagnostic is retained as a development/CI test executable,
not shipped or installed as a standalone command. The binary package contains
`vane`, `install.sh` and `uninstall.sh` plus configuration and documentation.

For a local build using previously downloaded dependencies, provide both
source trees or archives (the build script itself will not download them):

```sh
AWSLC_SOURCE=/path/to/aws-lc \
JSONC_SOURCE=/path/to/json-c \
AWSLC_REF=vX.Y.Z \
JSONC_REF=json-c-X.Y-YYYYMMDD \
./scripts/build-release.sh linux-amd64-v3
```

When the supplied archives are not Git checkouts, their exact commit IDs cannot
be recovered from those archives alone. This path is for local builds; official
binary release packaging requires valid 40-character dependency commit IDs and
the release verification checks.

## Release validation

The GitHub workflow separates validation from packaging:

1. Preflight checks the version source, release request, scripts, configuration,
   workflow markers, and release-document consistency.
2. GCC and Clang each build the native test suite with ASan and UBSan and run all
   tests.
3. Dependency tags and commits are resolved once, and a clean source archive is
   generated from the selected Git commit.
4. Each release architecture builds AWS-LC, json-c, and Vane from source,
   verifies the CPU flag on their actual compile commands, runs target tests,
   checks ELF hardening and dynamic dependencies, strips the binaries, and
   repeats process-level tests, including large TCP backpressure and FIN,
   against the stripped payload.
5. Before publication, the release job downloads every archive again, verifies
   its layout, checksums, architecture, embedded source archive, source commit,
   and ELF properties, and then creates the release checksum file.

Publishing is accepted only from the repository's default branch. A tag that
already points at the selected commit may be reused after an interrupted run,
but tags are never moved and existing GitHub releases or assets are never
modified.

A failed validation stage prevents packaging or publication.

## Source and binary archives

Source packaging must run from a clean Git checkout:

```sh
./scripts/package-source.sh dist
```

After a release build, create a binary archive with the matching source archive:

```sh
./scripts/package-release.sh \
  linux-amd64-v3 \
  build/linux-amd64-v3 \
  dist \
  dist/vane-$(cat VERSION)-src.tar.xz
```

Use `linux-arm64` and its corresponding build directory for ARM64.

## Diagnostic comparisons

Build `vane_probe_bench` explicitly to measure two-packet and eight-packet
ClientHello probe CPU cost using `tests/fixtures`. This diagnostic is not shipped
as a runtime command:

```sh
cmake --build build --target vane_probe_bench
./build/vane_probe_bench tests/fixtures
```

`tools/relay_bench.py OLD_BINARY NEW_BINARY OUTPUT_JSONL` alternates five local
TCP ping-pong and bulk comparisons with each Vane instance pinned to one CPU.
Compile its optional epoll-call counter first:

```sh
cc -O2 -shared -fPIC tools/epoll_counter.c -ldl -o tools/epoll_counter.so
python3 tools/relay_bench.py /path/to/old/vane /path/to/new/vane /tmp/relay.jsonl
```

The counter assumes this single-worker diagnostic only. Instrumented latency
is not used as a performance result. Python, loopback, host scheduling, and
kernel offloads limit what these comparisons establish; they are not WAN or
production-capacity measurements. No absolute speedup is a release gate.
