#!/usr/bin/env python3
"""Select one caller DMG and isolate the exact artifact set to upload."""

import glob
import os
from pathlib import Path
import shutil


def resolve(source, pattern, assets):
    source = Path(source).resolve()
    if Path(pattern).is_absolute():
        raise ValueError("dmg-path must be relative to the caller checkout")
    matches = [Path(match).resolve() for match in glob.glob(str(source / pattern))]
    if len(matches) != 1:
        raise ValueError("dmg-path must match exactly one file")
    archive = matches[0]
    if not archive.is_relative_to(source) or not archive.is_file() or archive.suffix != ".dmg":
        raise ValueError("DMG must be a regular .dmg file inside the caller checkout")
    if not all(character.isascii() and (character.isalnum() or character in '._-') for character in archive.name):
        raise ValueError("DMG filename must contain only ASCII letters, digits, dots, underscores, or hyphens")
    assets = Path(assets)
    assets.mkdir(mode=0o700)
    target = assets / archive.name
    shutil.copyfile(archive, target)
    return target.resolve()


if __name__ == "__main__":
    state = Path(os.environ["RELEASE_STATE_DIR"])
    assets = state.parent / (state.name + "-assets")
    archive = resolve(Path(os.environ["GITHUB_WORKSPACE"]) / "source", os.environ["DMG_PATTERN"], assets)
    os.environ["DMG_PATH"] = str(archive)
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as environment:
        environment.write(f"DMG_PATH={archive}\nRELEASE_ASSETS_DIR={assets}\n")
