#!/usr/bin/env python3
"""Inject installation failures entirely beneath a temporary VANE_ROOT."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MOCK = r'''import os, pathlib, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
phase=os.environ.get("VANE_FAIL_PHASE", "")
marker=pathlib.Path(os.environ["VANE_FAIL_MARKER"])
last=pathlib.Path(args[-1]).name if args else ""
first=pathlib.Path(args[-2]).name if len(args)>1 else ""
match=(name=="install" and ((phase=="prepare_binary" and last.startswith(".vane.new.")) or
       (phase=="prepare_config" and last.startswith(".vane.json.new."))))
match=match or (name=="chown" and phase=="prepare_service")
for product,stem in [("binary","vane"),("service","vane.service")]:
    match=match or (name=="mv" and phase=="backup_"+product and first==stem and ".old." in last)
    match=match or (name=="mv" and phase=="publish_"+product and ".new." in first and last==stem)
if match and not marker.exists():
    marker.write_text("failed")
    sys.exit(42)
if name=="id":
    print("0");sys.exit(0)
if name=="chown":sys.exit(0)
if name=="install":
    filtered=[];i=0
    while i<len(args):
        if args[i] in ("-o","-g"):i+=2
        else:filtered.append(args[i]);i+=1
    args=filtered
os.execv("/usr/bin/"+name,[name,*args])
'''


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: installer_regressions.py VANE_BINARY")
    binary = Path(sys.argv[1]).resolve()
    source = Path(__file__).resolve().parents[2]
    phases = ["prepare_binary", "prepare_service",
              "backup_binary", "backup_service",
              "publish_binary", "publish_service", "success"]
    cases = [(phase, True) for phase in phases]
    cases += [(phase, False) for phase in phases if not phase.startswith("backup_")]
    cases += [("prepare_config", False)]
    for phase, existing in cases:
        with tempfile.TemporaryDirectory(prefix="vane-install-") as directory:
            root = Path(directory); stage = root/"stage"; commands = root/"commands"
            commands.mkdir()
            for command in ["id", "install", "mv", "chown"]:
                path = commands/command
                path.write_text("#!"+sys.executable+"\n"+MOCK)
                path.chmod(0o755)
            paths = [stage/"usr/local/bin/vane", stage/"etc/systemd/system/vane.service"]
            for index, path in enumerate(paths):
                path.parent.mkdir(parents=True, exist_ok=True)
                if existing:
                    path.write_bytes(f"old file {index}\n".encode())
            legacy_probe = stage/"usr/local/bin/vane_udp_offload_probe"
            if existing:
                legacy_probe.write_bytes(b"old probe\n")
            config = stage/"etc/vane/vane.json"
            config.parent.mkdir(parents=True)
            if existing:
                config.write_bytes((source/"configs/vane.json").read_bytes())
            before = [path.read_bytes() if path.exists() else None for path in paths]
            env = {**os.environ, "PATH":str(commands)+os.pathsep+os.environ["PATH"],
                   "VANE_ROOT":str(stage), "VANE_BINARY":str(binary),
                   "VANE_FAIL_PHASE":phase,
                   "VANE_FAIL_MARKER":str(root/"failure")}
            result = subprocess.run(["sh", str(source/"install.sh")],
                                    env=env, capture_output=True, text=True, timeout=10)
            if phase=="success":
                assert result.returncode==0, result.stderr
                assert paths[0].read_bytes()==binary.read_bytes()
                assert not legacy_probe.exists(), "old runtime probe left by successful upgrade"
                service=paths[1].read_text()
                assert "Type=notify\n" in service and "NotifyAccess=main\n" in service
                assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" in service
            else:
                assert result.returncode!=0 and (root/"failure").exists(), (phase,result)
                assert [path.read_bytes() if path.exists() else None for path in paths]==before, phase
                assert legacy_probe.exists()==existing, "legacy probe mutated on failed upgrade"
            if existing or phase=="success":
                assert config.read_bytes()==(source/"configs/vane.json").read_bytes()
            else:
                assert not config.exists(), phase
            assert not list(stage.rglob("*.old.*")), phase
    print("installer rollback regressions passed")


if __name__ == "__main__":
    main()
