#!/usr/bin/env python3
"""Check complete uninstallation in temporary VANE_ROOT, with no host changes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

src=Path(__file__).resolve().parents[2]
for installed in (True, False):
    with tempfile.TemporaryDirectory(prefix='vane-uninstall-') as tmp:
        root=Path(tmp)/'staging'
        usr=root/'usr/local/bin'
        etc=root/'etc/systemd/system'
        conf=root/'etc/vane'
        usr.mkdir(parents=True);etc.mkdir(parents=True);conf.mkdir(parents=True)
        installed_files=[usr/'vane',usr/'vane_udp_offload_probe',etc/'vane.service',conf/'vane.json',conf/'secret.key',
                         root/'usr/local/share/vane/vane.json',root/'usr/local/share/doc/vane/README.md',
                         usr/'.vane.old.42',usr/'.vane_udp_offload_probe.new.55',etc/'.vane.service.old.16']
        if installed:
            for path in installed_files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('marker')
        unrelated=[usr/'another-tool',etc/'another.service',root/'etc/another-app/config']
        for path in unrelated:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('keep')
        commands=Path(tmp)/'commands';commands.mkdir()
        fake_id=commands/'id';fake_id.write_text('#!/bin/sh\nprintf "0\\n"\n');fake_id.chmod(0o755)
        env={**os.environ, 'VANE_ROOT':str(root), 'PATH':str(commands)+os.pathsep+os.environ['PATH']}
        for iteration in range(2):
            result=subprocess.run(['sh',str(src/'uninstall.sh')],env=env,capture_output=True,text=True,timeout=10)
            assert result.returncode==0,(installed,iteration,result.stderr)
            assert all(not path.exists() for path in installed_files), installed_files
            assert not conf.exists(),conf
            assert not (root/'usr/local/share/vane').exists()
            assert not (root/'usr/local/share/doc/vane').exists()
            assert all(path.read_text()=='keep' for path in unrelated),unrelated
print('uninstaller complete removal and idempotency regressions passed')
