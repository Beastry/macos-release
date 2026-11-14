#!/usr/bin/env python3
"""The same Xcode-free, no-secret validation entry point for CI and local use."""

from pathlib import Path
import shutil
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main():
    for script in sorted(ROOT.glob("scripts/*.sh")):
        subprocess.run(["bash", "-n", str(script)], check=True)
    for configuration in sorted((ROOT / ".github").rglob("*.yml")):
        parsed = yaml.load(configuration.read_text(), Loader=yaml.BaseLoader)
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected a YAML mapping: {configuration}")
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=True)
    actionlint = shutil.which("actionlint")
    if actionlint:
        subprocess.run([actionlint, "-shellcheck=", "-config-file", str(ROOT / ".github/actionlint.yaml")], cwd=ROOT, check=True)
    else:
        print("actionlint unavailable; YAML parsing and workflow policy tests passed")
    print("No-secret dry-run passed; no build, signing import, notary, or release API mutation ran")


if __name__ == "__main__":
    main()
