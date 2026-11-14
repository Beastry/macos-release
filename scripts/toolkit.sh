#!/bin/bash
set +x
set -euo pipefail
umask 077

operation="${1:?operation required}"
scripts_dir="$(cd "$(dirname "$0")" && pwd)"
state_dir="${RUNNER_TEMP:?}/macos-release-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"

case "$operation" in
  setup)
    if [ -z "${KEYCHAIN_PASSWORD:-}" ] || [ -z "${DEVELOPER_ID_P12_PASSWORD:-}" ]; then
      printf 'Missing signing password secret(s)\n' >&2
      exit 1
    fi
    mkdir -m 700 "$state_dir"
    export RELEASE_STATE_DIR="$state_dir"
    printf 'RELEASE_STATE_DIR=%s\nKEYCHAIN_PATH=%s\nASC_API_KEY_PATH=%s\nCODESIGN_FLAGS=--options runtime --timestamp\n' \
      "$state_dir" "$state_dir/signing.keychain-db" "$state_dir/AuthKey.p8" >> "$GITHUB_ENV"
    python3 - <<'PY'
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
state = Path(os.environ["RELEASE_STATE_DIR"])
original = subprocess.run(["security", "list-keychains", "-d", "user"], check=True, capture_output=True, text=True)
(state / "keychains.json").write_text(json.dumps(shlex.split(original.stdout)))
for variable, filename in (("DEVELOPER_ID_P12_BASE64", "identity.p12"), ("ASC_API_KEY_P8_BASE64", "AuthKey.p8")):
    try:
        content = base64.b64decode("".join(os.environ[variable].split()), validate=True)
        if not content:
            raise ValueError()
        (state / filename).write_bytes(content)
    except Exception:
        raise SystemExit("Invalid signing credential encoding (value suppressed)")
PY
    security create-keychain -p "$KEYCHAIN_PASSWORD" "$state_dir/signing.keychain-db" >/dev/null 2>&1
    security set-keychain-settings -lut 21600 "$state_dir/signing.keychain-db" >/dev/null 2>&1
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$state_dir/signing.keychain-db" >/dev/null 2>&1
    security import "$state_dir/identity.p12" -k "$state_dir/signing.keychain-db" -P "$DEVELOPER_ID_P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$state_dir/signing.keychain-db" >/dev/null 2>&1
    python3 - "$state_dir" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
state = Path(sys.argv[1])
subprocess.run(["security", "list-keychains", "-d", "user", "-s", str(state / "signing.keychain-db"),
                *json.loads((state / "keychains.json").read_text())], check=True, capture_output=True)
PY
    rm -f "$state_dir/identity.p12"
    ;;
  notarize)
    if [ "$ALREADY_NOTARIZED" = true ]; then
      xcrun stapler validate "$DMG_PATH" >/dev/null 2>&1
    else
      xcrun notarytool submit "$DMG_PATH" --key "$ASC_API_KEY_PATH" --key-id "$ASC_API_KEY_ID" \
        --issuer "$ASC_API_ISSUER_ID" --wait --timeout 90m >"$state_dir/notary-result.txt" 2>&1
      xcrun stapler staple "$DMG_PATH" >/dev/null 2>&1
      xcrun stapler validate "$DMG_PATH" >/dev/null 2>&1
    fi
    spctl --assess --type open --context context:primary-signature "$DMG_PATH" >/dev/null 2>&1
    ;;
  sparkle)
    mkdir "$state_dir/sparkle"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      https://github.com/sparkle-project/Sparkle/releases/download/2.8.1/Sparkle-2.8.1.tar.xz -o "$state_dir/sparkle.tar.xz"
    printf '5cddb7695674ef7704268f38eccaee80e3accbf19e61c1689efff5b6116d85be  %s\n' "$state_dir/sparkle.tar.xz" | shasum -a 256 -c -
    tar -xf "$state_dir/sparkle.tar.xz" -C "$state_dir/sparkle"
    export SIGN_UPDATE="$state_dir/sparkle/bin/sign_update"
    "$RELEASE_PYTHON" "$scripts_dir/release.py" appcast
    cp "$state_dir/metadata.json" "$(dirname "$DMG_PATH")/metadata.json"
    ;;
  cleanup)
    python3 "$scripts_dir/cleanup.py" "$state_dir"
    ;;
  *)
    printf 'Unknown operation\n' >&2
    exit 1
    ;;
esac
