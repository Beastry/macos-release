#!/usr/bin/env python3
"""Restore the keychain search list and remove per-run signing state."""

import json
from pathlib import Path
import shutil
import subprocess
import sys


def cleanup(state, run=subprocess.run):
    state = Path(state)
    if not state.exists():
        return
    failures = []

    def invoke(arguments):
        try:
            return run(arguments, capture_output=True).returncode == 0
        except OSError:
            return False

    mount = state / "mount"
    if mount.exists() and mount.is_mount():
        if not invoke(["hdiutil", "detach", str(mount)]):
            if not invoke(["hdiutil", "detach", "-force", str(mount)]):
                failures.append("DMG detach")
    original = state / "keychains.json"
    if original.exists():
        if not invoke(["security", "list-keychains", "-d", "user", "-s", *json.loads(original.read_text())]):
            failures.append("keychain search list restore")
    keychain = state / "signing.keychain-db"
    if keychain.exists():
        if not invoke(["security", "delete-keychain", str(keychain)]):
            failures.append("keychain delete")
    if "DMG detach" not in failures:
        shutil.rmtree(state)
    else:
        for entry in state.iterdir():
            if entry != mount:
                if entry.is_dir():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
    if failures:
        raise RuntimeError("Cleanup failed: " + ", ".join(failures))


if __name__ == "__main__":
    cleanup(sys.argv[1])
