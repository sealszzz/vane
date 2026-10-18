#!/usr/bin/env python3
"""Verify that every Vane C translation unit uses the release CPU flag."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: verify-compile-flags.py COMPILE_COMMANDS SOURCE_ROOT FLAG", file=sys.stderr)
        return 2

    commands_path = Path(sys.argv[1])
    source_root = Path(sys.argv[2]).resolve()
    required_flag = sys.argv[3]
    commands = json.loads(commands_path.read_text(encoding="utf-8"))
    checked: list[Path] = []
    missing: list[Path] = []

    for entry in commands:
        source = Path(entry["file"]).resolve()
        try:
            source.relative_to(source_root)
        except ValueError:
            continue
        if source.suffix not in {".c", ".cc", ".cpp", ".cxx", ".s", ".S"}:
            continue
        checked.append(source)
        arguments = entry.get("arguments")
        command = " ".join(arguments) if arguments else str(entry.get("command", ""))
        if required_flag not in command:
            missing.append(source)

    if not checked:
        print("no translation units found in compile_commands.json", file=sys.stderr)
        return 1
    if missing:
        for source in missing:
            print(f"missing {required_flag}: {source.relative_to(source_root)}", file=sys.stderr)
        return 1

    print(f"verified {required_flag} on {len(checked)} translation units")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
