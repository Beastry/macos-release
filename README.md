# macos-release

Minimal reusable **macOS Developer ID → notarization → Sparkle → draft GitHub
Release** automation for Beastry apps. From-scratch GPL-3.0-only implementation; see
[LICENSE](LICENSE), Copyright 2026 Beastry, and [license history](LICENSES/README.md).
No app-specific builds, Windows/Linux,
Homebrew, App Store upload, or Pages deployment.

## Call the workflow

Replace `REPLACE_WITH_FULL_40_CHARACTER_COMMIT_SHA` in **both** positions with the
same reviewed macos-release commit SHA. Do not use `main` or a floating tag.
`toolkit-ref` explicitly selects the toolkit's own scripts/composites; a reusable
workflow's normal checkout/context otherwise identifies the caller repository.

```yaml
name: Prepare macOS release
on:
  workflow_dispatch:
    inputs:
      tag:
        description: Version to prepare, e.g. v1.2.3
        required: true
        type: string
permissions:
  contents: read
jobs:
  release:
    permissions:
      contents: write
    uses: Beastry/macos-release/.github/workflows/release.yml@REPLACE_WITH_FULL_40_CHARACTER_COMMIT_SHA
    with:
      toolkit-ref: REPLACE_WITH_FULL_40_CHARACTER_COMMIT_SHA
      expected-repository: Beastry/YOUR_APP_REPOSITORY
      tag: ${{ inputs.tag }}
      package-command: ./scripts/package-release.sh
      dmg-path: dist/*.dmg
      hardware-requirements: arm64
    secrets:
      DEVELOPER_ID_P12_BASE64: ${{ secrets.DEVELOPER_ID_P12_BASE64 }}
      DEVELOPER_ID_P12_PASSWORD: ${{ secrets.DEVELOPER_ID_P12_PASSWORD }}
      DEVELOPER_ID_IDENTITY: ${{ secrets.DEVELOPER_ID_IDENTITY }}
      APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
      KEYCHAIN_PASSWORD: ${{ secrets.KEYCHAIN_PASSWORD }}
      ASC_API_KEY_ID: ${{ secrets.ASC_API_KEY_ID }}
      ASC_API_ISSUER_ID: ${{ secrets.ASC_API_ISSUER_ID }}
      ASC_API_KEY_P8_BASE64: ${{ secrets.ASC_API_KEY_P8_BASE64 }}
      SPARKLE_ED_PRIVATE_KEY: ${{ secrets.SPARKLE_ED_PRIVATE_KEY }}
```

The caller grants the maximum required permission. The toolkit reduces all jobs
to `contents: read` except the final draft-upload job (`contents: write`), which
receives **no signing secrets** and independently verifies signature, appcast,
checksum, and build ordering. No `id-token`, packages, org-admin scopes, or scope
refresh. **Do not use `secrets: inherit`.** No caller integration is installed by
this repo.

Real runs require the exact `expected-repository` under `Beastry/`, from a
default-branch `workflow_dispatch`/`push` or matching release-tag `push`. The source
commit must already be reachable from the caller's default branch. Keep the
calling workflow and packaging script reviewed on that branch. PR events,
`pull_request_target`, feature-branch dispatches and unrelated tag pushes cannot
reach signing jobs. A tag trigger only handles tags created by somebody else;
**dispatch is recommended and needs no tag**. Concurrency uses caller repo + tag,
with `cancel-in-progress: false`.

## Runner

The real workflow defaults to **`runs-on: xcode-27`** and
`XCODE_APP=/Applications/Xcode_27.app`; it runs `sudo xcode-select -s` when that
directory exists. This is an org **GitHub Actions-hosted** label, not a self-hosted
Mac mini, `macos-latest`, or `macos-15`. Supplied empirical evidence: successful
Beastry/stow Release run `42598211712`, labels `["xcode-27"]`, group `GitHub
Actions`, runner name such as `GitHub Actions 1000000621`. This is user-provided
runner evidence; no Stow source was consulted/copied.

Optional `runner-label` selects another compatible macOS runner with full Xcode,
Python 3.9+, `gh`, and internet access. Timeout defaults to 120 minutes (including
room for caller MLX builds). CI/dry-run use `ubuntu-latest`, no Xcode. The toolkit
does not install Xcode or replace apps.

## Caller-owned packaging

`package-command` runs from the caller checkout with bash `-e -o pipefail` after
signing setup. It owns building, entitlements, nested signing, XPC/MLX logic, and
DMG packaging; no app's `xcodebuild` commands are baked in. Only trusted commands
may run here. Do not enable tracing, print secrets, or put private files in output.

| Environment | Contract |
| --- | --- |
| `DEVELOPER_ID_IDENTITY` | Exact Developer ID Application identity name |
| `APPLE_TEAM_ID` | Expected signing team |
| `KEYCHAIN_PATH` | Unlocked temporary keychain; pass `--keychain "$KEYCHAIN_PATH"` |
| `CODESIGN_FLAGS` | `--options runtime --timestamp`; caller handles nested signing |
| `ASC_API_KEY_PATH` | Temporary private `.p8` file for notary API authentication |
| `ASC_API_KEY_ID`, `ASC_API_ISSUER_ID` | `notarytool --key-id` / `--issuer` values |
| `XCODE_APP` | `/Applications/Xcode_27.app` |
| `RELEASE_TAG`, `RELEASE_REPOSITORY` | Requested release tag and caller repository |

Produce **exactly one signed `.dmg`** matching relative `dmg-path` (default
`dist/*.dmg`) inside the checkout. Use an ASCII basename containing only letters,
digits, `.`, `_`, `-`. The toolkit copies only that file into an isolated output
directory. Quote `KEYCHAIN_PATH` explicitly rather than inserting a path with
spaces into a flags string. Prefer a checked-in packaging script. The package
step does not receive raw P12/base64/password environment variables.

The DMG must contain one top-level `.app`, or specify `app-relative-path` inside
the DMG. The toolkit mounts read-only, verifies strict/deep codesigning, exact
Developer ID authority, team and hardened runtime, then reads the packaged app's
`Contents/Info.plist`. Required fields (no guessed values):

- `CFBundleShortVersionString`: display version.
- `CFBundleVersion`: one to three numeric components, e.g. `123`, `1.2.3`.
- `SUPublicEDKey`: base64 Ed25519 public key matching the Sparkle secret.
- `LSMinimumSystemVersion`: minimum macOS version.
- `SUFeedURL`: exactly `https://github.com/<owner>/<repo>/releases/latest/download/appcast.xml`.

Default `already-notarized: false` submits the DMG with
`xcrun notarytool --key "$ASC_API_KEY_PATH" --key-id ... --issuer ...`, waits up
to 90 minutes, staples, and validates the staple/Gatekeeper. No local keychain
notary profile. If the caller already notarizes **and staples the DMG**, set
`already-notarized: true`: submission is skipped, validation still runs. App-only
notarization is not a separate v1 output. Signing/checksum generation happens
**after** stapling so the final DMG bytes are the ones Sparkle verifies.

## Appcast and draft shipping

Official Sparkle **2.8.1** tooling is fetched on the runner, not vendored, with
SHA-256 `5cddb7695674ef7704268f38eccaee80e3accbf19e61c1689efff5b6116d85be`.
`sign_update --ed-key-file -` receives the exported base64 private key via stdin,
never an argument or key file. Do not supply PEM. Independent Ed25519 verification
against packaged `SUPublicEDKey` fails closed on a mismatch or modified archive.

The one-item RSS feed includes build/display version, minimum OS, enclosure URL,
length, and `sparkle:edSignature`. `hardware-requirements` passes through to
`sparkle:hardwareRequirements` (e.g. `arm64`); empty default omits it. No deltas.
The caller's bundled Sparkle runtime must support any requested hardware filter.

If a latest published stable release has `appcast.xml`, the new build must be
**strictly higher** than every published build; numeric components are padded
to three for comparison. Both signing and upload jobs check. Missing latest
release/appcast permits initialization; malformed feeds or authentication/network
failures do not silently bypass ordering.

The API request sets `draft: true`, `prerelease: false`, `make_latest: "false"`,
and the exact caller source SHA. Only the DMG, `<filename>.dmg.sha256`, and
`appcast.xml` become Release assets. No git tag commands run. A normal dispatch
draft does not create its missing tag; a human publishing it later does.
Already-existing tags are never moved.

Reruns may replace these assets on an existing **draft** for the same tag/source
SHA. Any published release (also prerelease) is refused. Draft state is checked
before every upload. Upload is not transactional with a human concurrently
publishing: **wait for the run to finish before publishing/deleting its draft**.

**Human publishing is the ship switch.** Review artifacts, source and logs, then
publish as **stable/latest** in GitHub's UI. Drafts never become latest;
`make_latest: false` leaves latest promotion explicitly to the human. Prereleases
must not become latest and do not serve the stable latest-download feed. This
toolkit never publishes, undrafts, creates a tag, or pushes tags.

## Secrets and cleanup

Set these in the **caller repo → Settings → Secrets and variables → Actions**.
All nine are needed for a real run; workflow declarations are optional only so
dry-runs can pass none. Names only, never values:

| Secret | Purpose |
| --- | --- |
| `DEVELOPER_ID_P12_BASE64` | Base64 Developer ID Application P12 |
| `DEVELOPER_ID_P12_PASSWORD` | P12 import password |
| `DEVELOPER_ID_IDENTITY` | Exact Developer ID Application identity name |
| `APPLE_TEAM_ID` | Expected Apple signing team |
| `KEYCHAIN_PASSWORD` | Temporary signing keychain password |
| `ASC_API_KEY_ID` | App Store Connect API key ID |
| `ASC_API_ISSUER_ID` | App Store Connect API issuer ID |
| `ASC_API_KEY_P8_BASE64` | Base64 private `.p8` |
| `SPARKLE_ED_PRIVATE_KEY` | Exported Sparkle Ed25519 private key |

Org secrets work **only if an admin later grants selected-repo access**; no
existing org secrets are assumed/configured here. `github.token` handles GitHub
API calls, no PAT required. Optional **GitHub Environment required reviewers**
are possible later hardening, **not configured here**. No permission/billing
settings are changed.

Private state uses a per-run `RUNNER_TEMP` directory, umask 077. P12 is removed
right after import. `if: always()` cleanup restores the previous keychain search
list and removes the temporary keychain, P12, P8, notary/tooling files even on
failure. Cleanup failure fails the job. Only isolated public artifacts and
public plist metadata cross jobs as a one-day Actions artifact; metadata is not
a Release asset. Abrupt runner loss/forced termination cannot guarantee cleanup;
use disposable trusted hosted runners. Caller-created private files outside
toolkit state remain the caller's cleanup responsibility.

## No-secret tests / dry-run

Local (Python 3.9+, bash; no credentials/Xcode):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/validate.py
```

CI runs this same entry point on PRs and main pushes with read-only permissions:
throwaway Ed25519 matching/mismatching keys and tampering; XML/feed/hardware;
build ordering; mocked draft creation, published refusal and reruns; checksums;
DMG selection; mocked cleanup; `bash -n`; YAML parsing; workflow/pinning policies.
If available, `actionlint` runs too. `.github/actionlint.yaml` only tells that
linter the custom label; it does **not** classify the actual runner as self-hosted.

A caller can set `dry-run: true`, provide the three required inputs
(`toolkit-ref`, `expected-repository`, `tag`), omit **all** `secrets:` and grant
only `contents: read`. It runs this validation, not the caller package command;
no real DMG mount/build, credential import, Apple request, or release mutation.
PRs normally use the caller's own no-secret tests. Toolkit dry-run tests the
toolkit, not an app or real credential validity.

## Rollback / limits

Do not overwrite published releases/feeds or rewrite published build numbers.
Ship the desired prior code as a **higher build**, prepare a new draft, and
review/publish normally. Real end-to-end signing/notary validation requires a
separately authorized caller run on the configured runner. The Xcode-free tests
cannot establish Apple credential validity or successful real app distribution.
