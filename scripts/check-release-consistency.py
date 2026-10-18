#!/usr/bin/env python3
"""Validate release layout, wording, version ownership, and packaging gates."""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", VERSION):
    raise SystemExit("VERSION must contain exactly one x.y.z value")

text_roots = [
    ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "SECURITY.md", ROOT / "BUILDING.md",
    ROOT / "LICENSE", ROOT / "THIRD_PARTY_NOTICES.md",
    ROOT / "CMakeLists.txt", ROOT / "install.sh", ROOT / "uninstall.sh", ROOT / ".gitignore",
    ROOT / ".github", ROOT / "docs", ROOT / "configs", ROOT / "include",
    ROOT / "scripts", ROOT / "src", ROOT / "tests", ROOT / "tools",
]
version_hits: list[str] = []
version_token = re.compile(rf"(?<![0-9.]){re.escape(VERSION)}(?![0-9.])")
for root in text_roots:
    paths = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for path in paths:
        if path.suffix == ".bin" or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_bytes().decode("ascii")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"non-ASCII release text: {path.relative_to(ROOT)}") from exc
        # Treat VERSION as a dotted numeric token, not an arbitrary substring.
        # This avoids false positives such as the TEST-NET address 192.0.2.1.
        if version_token.search(text):
            version_hits.append(str(path.relative_to(ROOT)))
if version_hits:
    raise SystemExit("release version appears outside VERSION: " + ", ".join(version_hits))

with (ROOT / "configs/vane.json").open(encoding="ascii") as handle:
    json.load(handle)

required_files = [
    ".github/workflows/build.yml", "install.sh", "uninstall.sh", "configs/vane.json",
    "LICENSE", "THIRD_PARTY_NOTICES.md",
    "scripts/build-release.sh", "scripts/package-release.sh",
    "scripts/package-source.sh", "scripts/verify-release.sh",
    "scripts/verify-package.sh", "scripts/resolve-latest-dependencies.sh",
]
for name in required_files:
    if not (ROOT / name).is_file():
        raise SystemExit(f"missing release file: {name}")
for forbidden in [
    "packaging", "config", "docs/REVIEW.md", "docs/TESTING.md",
    "scripts/fetch-latest-deps.py",
]:
    if (ROOT / forbidden).exists():
        raise SystemExit(f"obsolete release path remains: {forbidden}")

cmake = (ROOT / "CMakeLists.txt").read_text(encoding="ascii")
for marker in [
    'project(vane VERSION "${VANE_VERSION_STRING}" LANGUAGES C)',
    'configs/vane.json', 'armv8-a', 'x86-64-v3',
    'VANE_JSONC_ROOT', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
]:
    if marker not in cmake:
        raise SystemExit(f"CMake release marker missing: {marker}")

workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="ascii")
for marker in [
    "linux-amd64-v3", "linux-arm64",
    "scripts/resolve-latest-dependencies.sh",
    "awslc_ref", "awslc_commit", "jsonc_ref", "jsonc_commit",
    "AWSLC_EXPECTED_COMMIT", "JSONC_EXPECTED_COMMIT",
    "scripts/check-release-consistency.py", "Sanitizers (${{ matrix.compiler }})",
    "scripts/verify-package.sh", "scripts/check-x86-64-v3.sh",
    "DEFAULT_BRANCH", 'refs/heads/$DEFAULT_BRANCH',
    "git ls-remote --tags origin", "release already exists",
]:
    if marker not in workflow:
        raise SystemExit(f"workflow release marker missing: {marker}")
for forbidden in [
    "vane-dependencies", "fetch-latest-deps.py",
    "needs.preflight.outputs.source_commit", "git tag -f", "git push --force",
    "gh release edit", "--clobber",
]:
    if forbidden in workflow:
        raise SystemExit(f"obsolete workflow design remains: {forbidden}")

build = (ROOT / "scripts/build-release.sh").read_text(encoding="ascii")
for marker in [
    "git clone --depth 1 --branch", "--recurse-submodules",
    "AWSLC_EXPECTED_COMMIT", "JSONC_EXPECTED_COMMIT",
    "https://github.com/aws/aws-lc.git",
    "https://github.com/json-c/json-c.git",
    'CMAKE_EXPORT_COMPILE_COMMANDS=ON', 'cmake --install "$AWSLC_BUILD"',
    "THIRD_PARTY_LICENSES/AWS-LC-LICENSE",
    "THIRD_PARTY_LICENSES/AWS-LC-NOTICE",
    "THIRD_PARTY_LICENSES/json-c-COPYING",
]:
    if marker not in build:
        raise SystemExit(f"release build marker missing: {marker}")

package = (ROOT / "scripts/package-release.sh").read_text(encoding="ascii")
verify_pos = package.find('scripts/verify-release.sh "$BUILD_DIR" "$TARGET"')
copy_pos = package.find('install -m 0755 "$BUILD_DIR/vane"')
if verify_pos < 0 or copy_pos < 0 or verify_pos > copy_pos:
    raise SystemExit("package-release must verify before staging binaries")
for marker in [
    "source archive does not match current Git commit", "VANE_TEST_RUNNER",
    "sha256sum -c", "BUILDING.md", "docs/ARCHITECTURE.md",
    "DEPENDENCIES", "THIRD_PARTY_NOTICES.md", "AWSLC_COMMIT", "JSONC_COMMIT",
]:
    if marker not in package:
        raise SystemExit(f"package gate missing: {marker}")

installer = (ROOT / "install.sh").read_text(encoding="ascii")
for marker in [
    "binary package is missing SHA256SUMS", "configuration validated before installation",
    "previous installation restored", "Vane pass-through TCP/QUIC SNI router",
    "Type=notify", "NotifyAccess=main",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
]:
    if marker not in installer:
        raise SystemExit(f"installer gate missing: {marker}")

all_docs = "\n".join((ROOT / name).read_text(encoding="ascii") for name in [
    "README.md", "SECURITY.md", "BUILDING.md", "docs/ARCHITECTURE.md",
    "docs/CONFIG.md", "docs/FEATURES.md",
])
for forbidden in [
    "transparent TCP", "Hard deletion occurs only", "every flow has a rolling 24-hour",
    "A new QUIC Initial for the same tuple replaces", "GCC static analysis",
    "fetch-latest-deps.py", "vane-dependencies",
]:
    if forbidden in all_docs:
        raise SystemExit(f"outdated documentation claim remains: {forbidden}")


for integration_name in ["integration_smoke.py", "udp_diagnostics.py", "tcp_half_close.py"]:
    integration = (ROOT / "tests/integration" / integration_name).read_text(encoding="ascii")
    for marker in ["VANE_TEST_RUNNER", "shlex.split"]:
        if marker not in integration:
            raise SystemExit(
                f"ARM64 integration runner support missing in {integration_name}: {marker}"
            )

integration_smoke = (ROOT / "tests/integration/integration_smoke.py").read_text(encoding="ascii")
for marker in [
    "def wait_udp_ready(",
    "wait_udp_ready(process, public_port, udp_fallback)",
    "Vane UDP forwarding path did not become ready",
]:
    if marker not in integration_smoke:
        raise SystemExit(f"UDP readiness regression gate missing: {marker}")

verify_release = (ROOT / "scripts/verify-release.sh").read_text(encoding="ascii")
for marker in [
    "VANE_SANITIZE:BOOL=OFF", "aws-lc-compile_commands.json",
    "json-c-compile_commands.json", "verify-compile-flags.py",
    "unexpected dynamic dependency", "x86 ISA needed:.*x86-64-v3",
    "third-party-licenses/AWS-LC-LICENSE", "invalid dependency commit metadata",
]:
    if marker not in verify_release:
        raise SystemExit(f"release verification marker missing: {marker}")

verify_package = (ROOT / "scripts/verify-package.sh").read_text(encoding="ascii")
for marker in [
    "embedded source archive mismatch", "unexpected dynamic dependency",
    "x86-64-v3 ELF property is missing", "package verification passed",
    "packaged project license mismatch", "dependency manifest must contain four lines",
]:
    if marker not in verify_package:
        raise SystemExit(f"asset verification marker missing: {marker}")

print("release consistency checks passed")
