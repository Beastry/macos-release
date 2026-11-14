#!/usr/bin/env python3
"""Small macOS release primitives. Never log signing credentials."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
from urllib.parse import quote
import xml.etree.ElementTree as ET

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ET.register_namespace("sparkle", SPARKLE)


def command(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, **kwargs)
    if result.returncode:
        raise ValueError(f"{Path(arguments[0]).name} failed; credential-bearing output suppressed")
    return result.stdout


def gh_api(endpoint, payload=None, missing_ok=False):
    arguments = ["gh", "api", endpoint]
    if payload is not None:
        arguments += ["--method", "POST", "--input", "-"]
    result = subprocess.run(
        arguments, input=json.dumps(payload) if payload is not None else None,
        capture_output=True, text=True,
    )
    if result.returncode:
        if missing_ok and "HTTP 404" in result.stderr:
            return None
        raise ValueError("GitHub API request failed; response suppressed")
    return json.loads(result.stdout)


def validate_repository(repository):
    if not re.fullmatch(r"Beastry/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Only official Beastry repositories are supported")


def validate_tag(tag):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag):
        raise ValueError("Tag must be a simple release version without slashes")


def feed_url(repository):
    validate_repository(repository)
    return f"https://github.com/{repository}/releases/latest/download/appcast.xml"


def build_number(value):
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", str(value), flags=re.ASCII):
        raise ValueError("Build numbers must contain one to three decimal components")
    components = tuple(int(part) for part in str(value).split("."))
    return components + (0,) * (3 - len(components))


def validate_metadata(metadata, repository):
    for key in ("CFBundleShortVersionString", "CFBundleVersion", "SUPublicEDKey", "LSMinimumSystemVersion"):
        if not isinstance(metadata.get(key), str) or not metadata[key].strip():
            raise ValueError(f"Missing packaged app metadata: {key}")
    build_number(metadata["CFBundleVersion"])
    public_key = base64.b64decode(metadata["SUPublicEDKey"], validate=True)
    if len(public_key) != 32:
        raise ValueError("SUPublicEDKey must encode a 32-byte Ed25519 public key")
    if metadata.get("SUFeedURL") != feed_url(repository):
        raise ValueError("Packaged SUFeedURL must use the official latest-release feed URL")


def verify_signature(archive, signature, public_key):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(signature, validate=True), Path(archive).read_bytes(),
        )
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Sparkle private key does not match packaged SUPublicEDKey or archive") from error


def check_build(metadata, published_feed):
    if published_feed is None:
        return
    root = ET.fromstring(published_feed)
    versions = [node.text for node in root.findall(f"./channel/item/{{{SPARKLE}}}version")]
    versions += [node.get(f"{{{SPARKLE}}}version") for node in root.findall("./channel/item/enclosure")
                 if node.get(f"{{{SPARKLE}}}version")]
    if not versions:
        raise ValueError("Published appcast contains no build numbers")
    if build_number(metadata["CFBundleVersion"]) <= max(build_number(version) for version in versions):
        raise ValueError("New build must be higher than every build in the published appcast")


def write_checksum(archive):
    archive = Path(archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    output = archive.with_name(archive.name + ".sha256")
    output.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    return output


def write_appcast(archive, metadata, signature, repository, tag, hardware, output, published_feed=None):
    validate_repository(repository)
    validate_tag(tag)
    validate_metadata(metadata, repository)
    verify_signature(archive, signature, metadata["SUPublicEDKey"])
    check_build(metadata, published_feed)
    root = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "title").text = f"{repository} updates"
    ET.SubElement(channel, "link").text = feed_url(repository)
    item = ET.SubElement(channel, "item")
    ET.SubElement(item, "title").text = metadata["CFBundleShortVersionString"]
    for name, value in (
        ("version", metadata["CFBundleVersion"]),
        ("shortVersionString", metadata["CFBundleShortVersionString"]),
        ("minimumSystemVersion", metadata["LSMinimumSystemVersion"]),
    ):
        ET.SubElement(item, f"{{{SPARKLE}}}{name}").text = value
    if hardware:
        ET.SubElement(item, f"{{{SPARKLE}}}hardwareRequirements").text = hardware
    ET.SubElement(item, "enclosure", {
        "url": f"https://github.com/{repository}/releases/download/{quote(tag, safe='')}/{quote(Path(archive).name, safe='')}",
        "length": str(Path(archive).stat().st_size),
        "type": "application/octet-stream",
        f"{{{SPARKLE}}}edSignature": signature,
    })
    ET.indent(root)
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)


def require_draft(release):
    if release is not None and release.get("draft") is not True:
        raise ValueError("Refusing to modify an already published release")


def existing_release(repository, tag):
    return gh_api(f"repos/{repository}/releases/tags/{quote(tag, safe='')}", missing_ok=True)


def published_feed(repository):
    latest = gh_api(f"repos/{repository}/releases/latest", missing_ok=True)
    if latest is None:
        return None
    if latest.get("draft") or latest.get("prerelease"):
        raise ValueError("Latest release unexpectedly refers to a draft or prerelease")
    assets = [asset for asset in latest["assets"] if asset["name"] == "appcast.xml"]
    if not assets:
        return None
    return command(["gh", "api", f"repos/{repository}/releases/assets/{assets[0]['id']}",
                    "-H", "Accept: application/octet-stream"])


def draft_release(repository, tag, target, directory):
    validate_repository(repository)
    validate_tag(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", target):
        raise ValueError("Release target must be the exact source commit SHA")
    directory = Path(directory)
    archives = list(directory.glob("*.dmg"))
    if len(archives) != 1:
        raise ValueError("Release directory must contain exactly one DMG")
    archive = archives[0]
    metadata = json.loads((directory / "metadata.json").read_text())
    root = ET.parse(directory / "appcast.xml").getroot()
    enclosure = root.find("./channel/item/enclosure")
    if enclosure is None:
        raise ValueError("Missing appcast enclosure")
    signature = enclosure.get(f"{{{SPARKLE}}}edSignature")
    expected = directory / "verified-appcast.xml"
    write_appcast(archive, metadata, signature, repository, tag,
                  root.findtext(f"./channel/item/{{{SPARKLE}}}hardwareRequirements", ""),
                  expected, published_feed(repository))
    if expected.read_bytes() != (directory / "appcast.xml").read_bytes():
        raise ValueError("Appcast does not describe the release artifact")
    expected.unlink()
    checksum = archive.with_name(archive.name + ".sha256")
    if checksum.read_text() != f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n":
        raise ValueError("Checksum does not match release artifact")
    release = existing_release(repository, tag)
    require_draft(release)
    if release is None:
        release = gh_api(f"repos/{repository}/releases", {
            "tag_name": tag, "target_commitish": target, "name": tag,
            "body": "Draft only. Review signatures, notarization, and assets before publishing.",
            "draft": True, "prerelease": False, "make_latest": "false",
        })
        require_draft(release)
    elif release.get("target_commitish") != target:
        raise ValueError("Existing draft targets a different source commit; refusing to mix artifacts")
    for asset in (archive, checksum, directory / "appcast.xml"):
        current = existing_release(repository, tag)
        if current is None or current["id"] != release["id"]:
            raise ValueError("Draft release disappeared or changed during upload")
        require_draft(current)
        command(["gh", "release", "upload", tag, str(asset), "--repo", repository, "--clobber"])


def inspect_dmg(archive, state, repository, app_path):
    mount = Path(state) / "mount"
    mount.mkdir()
    command(["hdiutil", "attach", str(archive), "-readonly", "-nobrowse", "-plist", "-mountpoint", str(mount)])
    try:
        if app_path:
            app = (mount / app_path).resolve()
            if not app.is_relative_to(mount.resolve()) or app.suffix != ".app":
                raise ValueError("app-relative-path must identify an app inside the DMG")
        else:
            apps = list(mount.glob("*.app"))
            if len(apps) != 1:
                raise ValueError("DMG must contain one top-level app or specify app-relative-path")
            app = apps[0]
        command(["codesign", "--verify", "--deep", "--strict", str(app)])
        result = subprocess.run(["codesign", "-d", "--verbose=4", str(app)], capture_output=True, text=True)
        if result.returncode or f"TeamIdentifier={os.environ['APPLE_TEAM_ID']}" not in result.stderr.splitlines():
            raise ValueError("Packaged app is not signed by the expected Apple team")
        if f"Authority={os.environ['DEVELOPER_ID_IDENTITY']}" not in result.stderr.splitlines():
            raise ValueError("Packaged app does not use the expected Developer ID identity")
        if not re.search(r"flags=.*\bruntime\b", result.stderr):
            raise ValueError("Packaged app must enable hardened runtime")
        metadata = plistlib.loads((app / "Contents/Info.plist").read_bytes())
        validate_metadata(metadata, repository)
        selected = {key: metadata[key] for key in (
            "CFBundleShortVersionString", "CFBundleVersion", "SUPublicEDKey", "LSMinimumSystemVersion", "SUFeedURL",
        )}
        (Path(state) / "metadata.json").write_text(json.dumps(selected), encoding="utf-8")
    finally:
        command(["hdiutil", "detach", str(mount)])
        mount.rmdir()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["inspect", "appcast", "draft", "preflight"])
    arguments = parser.parse_args()
    repository = os.environ["RELEASE_REPOSITORY"]
    tag = os.environ["RELEASE_TAG"]
    validate_repository(repository)
    validate_tag(tag)
    if arguments.operation == "preflight":
        require_draft(existing_release(repository, tag))
    elif arguments.operation == "inspect":
        inspect_dmg(Path(os.environ["DMG_PATH"]), os.environ["RELEASE_STATE_DIR"], repository,
                    os.environ.get("APP_RELATIVE_PATH", ""))
    elif arguments.operation == "appcast":
        archive = Path(os.environ["DMG_PATH"])
        metadata = json.loads(Path(os.environ["RELEASE_STATE_DIR"], "metadata.json").read_text())
        validate_metadata(metadata, repository)
        feed = published_feed(repository)
        check_build(metadata, feed)
        signature = command([os.environ["SIGN_UPDATE"], "--ed-key-file", "-", "-p", str(archive)],
                            input=os.environ["SPARKLE_ED_PRIVATE_KEY"].encode()).decode().strip()
        write_appcast(archive, metadata, signature, repository, tag,
                      os.environ.get("HARDWARE_REQUIREMENTS", ""), archive.parent / "appcast.xml", feed)
        write_checksum(archive)
    elif arguments.operation == "draft":
        draft_release(repository, tag, os.environ["RELEASE_TARGET"], os.environ["RELEASE_ASSETS_DIR"])


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Release validation or command failed; details suppressed to protect credentials. Run no-secret tests for diagnostics.", file=sys.stderr)
        sys.exit(1)
