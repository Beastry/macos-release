import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import cleanup
import release
import resolve_dmg


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / "Example.dmg"
        self.archive.write_bytes(b"Throwaway fake DMG: never mounted or shipped")
        self.private = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.signature = base64.b64encode(self.private.sign(self.archive.read_bytes())).decode()
        self.metadata = {
            "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "123",
            "SUPublicEDKey": self.public, "LSMinimumSystemVersion": "14.0",
            "SUFeedURL": release.feed_url("Beastry/example"),
        }
        self.output = self.directory / "appcast.xml"
        self.draft = {"draft": True, "id": 42, "tag_name": "v1.2.3", "target_commitish": "a" * 40}

    def generate(self, hardware="", feed=None):
        release.write_appcast(self.archive, self.metadata, self.signature,
                              "Beastry/example", "v1.2.3", hardware, self.output, feed)
        return ET.parse(self.output).getroot()

    def prepare_assets(self):
        self.generate()
        release.write_checksum(self.archive)
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))

    def test_appcast_shape_feed_and_signature(self):
        root = self.generate()
        self.assertEqual(root.tag, "rss")
        self.assertEqual(root.get("version"), "2.0")
        self.assertEqual(len(root.findall("./channel/item")), 1)
        self.assertEqual(root.findtext("./channel/link"),
                         "https://github.com/Beastry/example/releases/latest/download/appcast.xml")
        item = root.find("./channel/item")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}version"), "123")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}shortVersionString"), "1.2.3")
        self.assertEqual(item.findtext(f"{{{release.SPARKLE}}}minimumSystemVersion"), "14.0")
        enclosure = item.find("enclosure")
        self.assertEqual(enclosure.get("url"), "https://github.com/Beastry/example/releases/download/v1.2.3/Example.dmg")
        self.assertEqual(enclosure.get("length"), str(self.archive.stat().st_size))
        self.assertEqual(enclosure.get(f"{{{release.SPARKLE}}}edSignature"), self.signature)

    def test_hardware_requirements_passthrough(self):
        self.assertEqual(self.generate("arm64").findtext(
            f"./channel/item/{{{release.SPARKLE}}}hardwareRequirements"), "arm64")
        self.assertIsNone(self.generate().find(f"./channel/item/{{{release.SPARKLE}}}hardwareRequirements"))

    def test_throwaway_matching_key(self):
        release.verify_signature(self.archive, self.signature, self.public)

    def test_mismatched_key_fails_before_writing_feed(self):
        self.metadata["SUPublicEDKey"] = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_tampered_archive_fails(self):
        self.archive.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.generate()

    def test_metadata_required_and_feed_must_match(self):
        for key in self.metadata:
            metadata = self.metadata.copy()
            del metadata[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.validate_metadata(metadata, "Beastry/example")
        self.metadata["SUFeedURL"] = "https://untrusted.example/feed"
        with self.assertRaises(ValueError):
            self.generate()

    def test_build_never_regresses_or_repeats(self):
        self.generate()
        old_feed = self.output.read_bytes()
        for build in ("122", "123", "123.0.0"):
            self.metadata["CFBundleVersion"] = build
            with self.subTest(build=build), self.assertRaisesRegex(ValueError, "higher"):
                self.generate(feed=old_feed)
        self.metadata["CFBundleVersion"] = "124"
        self.generate(feed=old_feed)

    def test_legacy_enclosure_build_and_invalid_feed(self):
        feed = f'<rss xmlns:sparkle="{release.SPARKLE}"><channel><item><enclosure sparkle:version="124"/></item></channel></rss>'
        with self.assertRaises(ValueError):
            release.check_build(self.metadata, feed)
        with self.assertRaises(ValueError):
            release.check_build(self.metadata, "<rss/>")
        with self.assertRaises(ValueError):
            release.build_number("1-beta")
        self.assertGreater(release.build_number("1.10"), release.build_number("1.9.9"))

    def test_checksum_writing(self):
        result = release.write_checksum(self.archive)
        self.assertEqual(result.name, "Example.dmg.sha256")
        self.assertEqual(result.read_text(), f"{hashlib.sha256(self.archive.read_bytes()).hexdigest()}  Example.dmg\n")

    def test_published_release_refused(self):
        release.require_draft(None)
        release.require_draft({"draft": True})
        for published in ({"draft": False}, {"draft": False, "prerelease": True}, {}):
            with self.subTest(release=published), self.assertRaisesRegex(ValueError, "published"):
                release.require_draft(published)

    def draft_api(self, pages=None, created=None, checks=None, assets=None):
        pages = pages if pages is not None else [[self.draft]]
        checks = iter(checks) if checks is not None else None
        assets = assets if assets is not None else [[]]

        def respond(endpoint, payload=None, missing_ok=False, method=None):
            if endpoint == "repos/Beastry/example/releases" and payload is not None:
                return created if created is not None else self.draft.copy()
            if endpoint.startswith("repos/Beastry/example/releases?per_page=100&page="):
                return pages[int(endpoint.rsplit("=", 1)[1]) - 1]
            if endpoint == "repos/Beastry/example/releases/42":
                self.assertTrue(missing_ok)
                return next(checks) if checks is not None else self.draft.copy()
            if endpoint.startswith("repos/Beastry/example/releases/42/assets?per_page=100&page="):
                return assets[int(endpoint.rsplit("=", 1)[1]) - 1]
            if endpoint.startswith("repos/Beastry/example/releases/assets/") and method == "DELETE":
                return None
            self.fail(f"Unexpected GitHub API call: {endpoint}")

        return Mock(side_effect=respond)

    def run_draft(self, api, upload=None):
        with patch.object(release, "published_feed", return_value=None), \
             patch.object(release, "gh_api", api), patch.object(release, "command", upload or Mock()) as command:
            release.draft_release("Beastry/example", "v1.2.3", "a" * 40, self.directory)
        return command

    def test_create_untagged_draft_rereads_id_before_upload(self):
        self.prepare_assets()
        api = self.draft_api(pages=[[]])
        events = Mock()
        events.attach_mock(api, "api")
        upload = Mock()
        events.attach_mock(upload, "upload")
        self.run_draft(api, upload)
        creation = api.call_args_list[1]
        payload = creation.args[1]
        self.assertEqual(creation.args[0], "repos/Beastry/example/releases")
        self.assertIs(payload["draft"], True)
        self.assertIs(payload["prerelease"], False)
        self.assertEqual(payload["make_latest"], "false")
        self.assertEqual(payload["target_commitish"], "a" * 40)
        first_upload = next(index for index, event in enumerate(events.mock_calls) if event[0] == "upload")
        self.assertEqual(events.mock_calls[first_upload - 1],
                         call.api("repos/Beastry/example/releases/42", missing_ok=True))
        self.assertEqual(upload.call_count, 3)
        for invocation, asset in zip(upload.call_args_list,
                                    (self.archive, self.archive.with_suffix(".dmg.sha256"), self.output)):
            self.assertEqual(invocation.args[0], ["gh", "api",
                f"https://uploads.github.com/repos/Beastry/example/releases/42/assets?name={asset.name}",
                "--method", "POST", "-H", "Content-Type: application/octet-stream", "--input", str(asset)])

    def test_matching_existing_draft_resumes_with_uploads(self):
        self.prepare_assets()
        api = self.draft_api()
        upload = self.run_draft(api)
        self.assertEqual(upload.call_count, 3)
        self.assertTrue(all(len(invocation.args) == 1 for invocation in api.call_args_list))
        self.assertIn(call("repos/Beastry/example/releases?per_page=100&page=1"), api.call_args_list)
        self.assertIn(call("repos/Beastry/example/releases/42", missing_ok=True), api.call_args_list)

    def test_matching_draft_on_later_page(self):
        self.prepare_assets()
        api = self.draft_api(pages=[[{**self.draft, "tag_name": f"v0.{index}"} for index in range(100)],
                                    [self.draft]])
        upload = self.run_draft(api)
        self.assertEqual(upload.call_count, 3)
        self.assertIn(call("repos/Beastry/example/releases?per_page=100&page=2"), api.call_args_list)

    def test_invalid_existing_draft_causes_no_mutation(self):
        self.prepare_assets()
        for changes, message in (({"draft": False}, "published"),
                                 ({"target_commitish": "b" * 40}, "source commit"),
                                 ({"target_commitish": "main"}, "source commit")):
            with self.subTest(changes=changes):
                api = self.draft_api(pages=[[{**self.draft, **changes}]])
                upload = Mock()
                with self.assertRaisesRegex(ValueError, message):
                    self.run_draft(api, upload)
                upload.assert_not_called()
                self.assertEqual(api.call_count, 1)

    def test_invalid_creation_or_id_read_causes_no_mutation(self):
        self.prepare_assets()
        for changes in ({"draft": False}, {"tag_name": "v9.9.9"},
                        {"target_commitish": "b" * 40}, {"id": None}):
            for stage in ("create", "read"):
                with self.subTest(changes=changes, stage=stage):
                    invalid = {**self.draft, **changes}
                    api = self.draft_api(pages=[[]], created=invalid) if stage == "create" else \
                        self.draft_api(checks=[invalid])
                    upload = Mock()
                    with self.assertRaises(ValueError):
                        self.run_draft(api, upload)
                    upload.assert_not_called()
                    self.assertFalse(any(invocation.kwargs.get("method") == "DELETE"
                                         for invocation in api.call_args_list))

    def test_concurrent_change_aborts_further_uploads(self):
        self.prepare_assets()
        for changes in (None, {"id": 43}, {"draft": False}, {"tag_name": "v9.9.9"},
                        {"target_commitish": "b" * 40}):
            for completed in (0, 1, 2):
                with self.subTest(changes=changes, completed=completed):
                    changed = None if changes is None else {**self.draft, **changes}
                    api = self.draft_api(checks=[self.draft] * (completed * 3) + [changed])
                    upload = Mock()
                    with self.assertRaises(ValueError):
                        self.run_draft(api, upload)
                    self.assertEqual(upload.call_count, completed)

    def test_final_upload_is_checked_for_concurrent_publish(self):
        self.prepare_assets()
        api = self.draft_api(checks=[self.draft] * 8 + [{**self.draft, "draft": False}])
        upload = Mock()
        with self.assertRaisesRegex(ValueError, "published"):
            self.run_draft(api, upload)
        self.assertEqual(upload.call_count, 3)

    def test_clobber_deletes_only_matching_assets_including_later_page(self):
        self.prepare_assets()
        api = self.draft_api(assets=[[{"id": index, "name": f"keep-{index}"} for index in range(100)],
                                    [{"id": 101, "name": self.archive.name}]])
        events = Mock()
        events.attach_mock(api, "api")
        upload = Mock()
        events.attach_mock(upload, "upload")
        self.run_draft(api, upload)
        deletions = [invocation for invocation in api.call_args_list if invocation.kwargs.get("method") == "DELETE"]
        self.assertEqual(deletions, [call("repos/Beastry/example/releases/assets/101", method="DELETE")])
        deletion_index = events.mock_calls.index(call.api("repos/Beastry/example/releases/assets/101", method="DELETE"))
        self.assertEqual(events.mock_calls[deletion_index - 1],
                         call.api("repos/Beastry/example/releases/42", missing_ok=True))
        self.assertEqual(events.mock_calls[deletion_index + 1],
                         call.api("repos/Beastry/example/releases/42", missing_ok=True))
        self.assertEqual(events.mock_calls[deletion_index + 2][0], "upload")
        self.assertEqual(upload.call_count, 3)

    def test_clobber_rechecks_before_delete_and_replacement(self):
        self.prepare_assets()
        for successful_checks in (1, 2):
            with self.subTest(successful_checks=successful_checks):
                api = self.draft_api(checks=[self.draft] * successful_checks + [{**self.draft, "draft": False}],
                                     assets=[[{"id": 101, "name": self.archive.name}]])
                upload = Mock()
                with self.assertRaisesRegex(ValueError, "published"):
                    self.run_draft(api, upload)
                upload.assert_not_called()
                deletions = [invocation for invocation in api.call_args_list if invocation.kwargs.get("method") == "DELETE"]
                self.assertEqual(len(deletions), successful_checks - 1)

    def test_ambiguous_release_tag_refused(self):
        self.prepare_assets()
        api = self.draft_api(pages=[[self.draft] * 100, [{**self.draft, "id": 43}]])
        upload = Mock()
        with self.assertRaisesRegex(ValueError, "Multiple releases"):
            self.run_draft(api, upload)
        upload.assert_not_called()

    def test_untagged_draft_through_gh_transport(self):
        self.prepare_assets()
        responses = [[], self.draft, self.draft, [], self.draft, {"id": 101}, self.draft,
                     self.draft, [], self.draft, {"id": 102}, self.draft,
                     self.draft, [], self.draft, {"id": 103}, self.draft]
        with patch.object(release, "published_feed", return_value=None), \
             patch.object(release.subprocess, "run", side_effect=[
                 subprocess.CompletedProcess([], 0, json.dumps(response), "") for response in responses]) as run:
            release.draft_release("Beastry/example", "v1.2.3", "a" * 40, self.directory)
        self.assertEqual(run.call_args_list[0].args[0],
                         ["gh", "api", "repos/Beastry/example/releases?per_page=100&page=1"])
        self.assertEqual(run.call_args_list[1].args[0],
                         ["gh", "api", "repos/Beastry/example/releases", "--method", "POST", "--input", "-"])
        self.assertEqual(run.call_args_list[2].args[0],
                         ["gh", "api", "repos/Beastry/example/releases/42"])
        self.assertEqual(run.call_count, len(responses))
        uploads = [invocation for invocation in run.call_args_list
                   if invocation.args[0][2].startswith("https://uploads.github.com/")]
        self.assertEqual(len(uploads), 3)
        for invocation in uploads:
            self.assertEqual(invocation.args[0][-2], "--input")
            self.assertTrue(Path(invocation.args[0][-1]).is_file())

    def test_asset_failures_abort_without_further_uploads(self):
        self.prepare_assets()
        for operation in ("delete", "upload"):
            with self.subTest(operation=operation):
                api = self.draft_api(assets=[[{"id": 101, "name": self.archive.name}]])
                respond = api.side_effect

                def fail_delete(endpoint, *arguments, **kwargs):
                    if kwargs.get("method") == "DELETE":
                        raise ValueError("GitHub API request failed; response suppressed")
                    return respond(endpoint, *arguments, **kwargs)

                if operation == "delete":
                    api.side_effect = fail_delete
                upload = Mock(side_effect=ValueError("gh failed; credential-bearing output suppressed"))
                with self.assertRaisesRegex(ValueError, "suppressed"):
                    self.run_draft(api, upload)
                self.assertEqual(upload.call_count, 0 if operation == "delete" else 1)

    def test_gh_api_empty_delete_and_suppressed_errors(self):
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertIsNone(release.gh_api("repos/Beastry/example/releases/assets/101", method="DELETE"))
            self.assertEqual(run.call_args.args[0],
                             ["gh", "api", "repos/Beastry/example/releases/assets/101", "--method", "DELETE"])
        for status in ("HTTP 403", "HTTP 404"):
            with self.subTest(status=status), patch.object(release.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 1, "private response", status)):
                with self.assertRaisesRegex(ValueError, "^GitHub API request failed; response suppressed$"):
                    release.gh_api("repos/Beastry/example/releases?per_page=100&page=1")
                if status == "HTTP 404":
                    self.assertIsNone(release.gh_api("repos/Beastry/example/releases/42", missing_ok=True))

    def test_checksum_tampering_prevents_mutation(self):
        self.prepare_assets()
        self.archive.with_name("Example.dmg.sha256").write_text("wrong\n")
        with patch.object(release, "published_feed", return_value=None), patch.object(release, "gh_api") as api:
            with self.assertRaisesRegex(ValueError, "Checksum"):
                release.draft_release("Beastry/example", "v1.2.3", "a" * 40, self.directory)
            api.assert_not_called()

    def test_latest_feed_read_failure_not_silently_ignored(self):
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "HTTP 403")):
            with self.assertRaises(ValueError):
                release.published_feed("Beastry/example")
        with patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "HTTP 404")):
            self.assertIsNone(release.published_feed("Beastry/example"))

    def test_signer_uses_stdin_and_never_exposes_private_key(self):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        environment = {
            "RELEASE_REPOSITORY": "Beastry/example", "RELEASE_TAG": "v1.2.3",
            "DMG_PATH": str(self.archive), "RELEASE_STATE_DIR": str(self.directory),
            "SIGN_UPDATE": "/throwaway/sign_update", "SPARKLE_ED_PRIVATE_KEY": "throwaway-test-value",
        }
        with patch.dict(os.environ, environment), patch.object(sys, "argv", ["release.py", "appcast"]), \
             patch.object(release, "published_feed", return_value=None), \
             patch.object(release, "command", return_value=self.signature.encode()) as command:
            release.main()
            self.assertEqual(command.call_args.args[0][1:4], ["--ed-key-file", "-", "-p"])
            self.assertNotIn("throwaway-test-value", command.call_args.args[0])
            self.assertEqual(command.call_args.kwargs["input"], b"throwaway-test-value")

    def test_inspect_dmg_reads_packaged_plist_and_detaches(self):
        mount = self.directory / "mount"

        def fake_command(arguments, **kwargs):
            if arguments[:2] == ["hdiutil", "attach"]:
                contents = mount / "Example.app/Contents"
                contents.mkdir(parents=True)
                (contents / "Info.plist").write_bytes(plistlib.dumps(self.metadata))
            elif arguments[:2] == ["hdiutil", "detach"]:
                shutil.rmtree(mount / "Example.app")
            return b""

        with patch.object(release, "command", side_effect=fake_command) as command, \
             patch.object(release.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "",
                 "TeamIdentifier=TESTTEAM\nAuthority=Developer ID Application: Throwaway\nCodeDirectory flags=0x10000(runtime)\n")), \
             patch.dict(os.environ, {"APPLE_TEAM_ID": "TESTTEAM", "DEVELOPER_ID_IDENTITY": "Developer ID Application: Throwaway"}):
            release.inspect_dmg(self.archive, self.directory, "Beastry/example", "")
            self.assertEqual(json.loads((self.directory / "metadata.json").read_text()), self.metadata)
            self.assertEqual(command.call_args.args[0][:2], ["hdiutil", "detach"])

    def test_inspect_failure_still_detaches(self):
        with patch.object(release, "command", return_value=b"") as command:
            with self.assertRaisesRegex(ValueError, "one top-level app"):
                release.inspect_dmg(self.archive, self.directory, "Beastry/example", "")
            self.assertEqual(command.call_args.args[0][:2], ["hdiutil", "detach"])
            self.assertFalse((self.directory / "mount").exists())

    def test_detach_may_already_remove_mount_directory(self):
        def fake_command(arguments, **kwargs):
            if arguments[:2] == ["hdiutil", "detach"]:
                (self.directory / "mount").rmdir()
            return b""

        with patch.object(release, "command", side_effect=fake_command):
            with self.assertRaisesRegex(ValueError, "one top-level app"):
                release.inspect_dmg(self.archive, self.directory, "Beastry/example", "")
            self.assertFalse((self.directory / "mount").exists())


class CleanupTests(unittest.TestCase):
    def test_cleanup_restores_search_list_and_deletes_all_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "keychains.json").write_text(json.dumps(["/original/login.keychain-db"]))
            for name in ("signing.keychain-db", "identity.p12", "AuthKey.p8", "notary-result.txt"):
                (state / name).write_bytes(b"throwaway")
            run = Mock(return_value=subprocess.CompletedProcess([], 0))
            cleanup.cleanup(state, run)
            self.assertFalse(state.exists())
            self.assertEqual(run.call_args_list[0].args[0], [
                "security", "list-keychains", "-d", "user", "-s", "/original/login.keychain-db"])
            self.assertEqual(run.call_args_list[1].args[0][:2], ["security", "delete-keychain"])
            cleanup.cleanup(state, run)

    def test_cleanup_command_failure_still_removes_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "signing.keychain-db").touch()
            (state / "AuthKey.p8").write_text("throwaway")
            with self.assertRaises(RuntimeError):
                cleanup.cleanup(state, Mock(side_effect=FileNotFoundError()))
            self.assertFalse(state.exists())

    def test_empty_detached_mount_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            (state / "mount").mkdir(parents=True)
            run = Mock(return_value=subprocess.CompletedProcess([], 1))
            cleanup.cleanup(state, run)
            self.assertFalse(state.exists())
            run.assert_not_called()

    def test_stuck_mount_preserves_mount_but_removes_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            mount = state / "mount"
            mount.mkdir(parents=True)
            (state / "AuthKey.p8").write_text("throwaway")
            run = Mock(return_value=subprocess.CompletedProcess([], 1))
            with patch.object(Path, "is_mount", return_value=True), self.assertRaises(RuntimeError):
                cleanup.cleanup(state, run)
            self.assertTrue(mount.exists())
            self.assertFalse((state / "AuthKey.p8").exists())
            self.assertEqual(run.call_count, 2)


class ResolveTests(unittest.TestCase):
    def test_exactly_one_dmg_and_no_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Example.dmg").write_bytes(b"test")
            result = resolve_dmg.resolve(source, "*.dmg", root / "assets")
            self.assertEqual(result.read_bytes(), b"test")
            (source / "Second.dmg").touch()
            with self.assertRaises(ValueError):
                resolve_dmg.resolve(source, "*.dmg", root / "other")
            with self.assertRaises(ValueError):
                resolve_dmg.resolve(source, "../assets/Example.dmg", root / "other")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)

    def test_all_external_actions_have_full_sha_pins(self):
        for filename in (ROOT / ".github").rglob("*.yml"):
            text = filename.read_text()
            self.assertNotIn("secrets: inherit", text)
            for action in re.findall(r"uses:\s*([^\s]+)", text):
                if not action.startswith("./"):
                    self.assertRegex(action, r"^[\w-]+/[\w-]+@[0-9a-f]{40}$")

    def test_secret_job_events_and_minimum_permissions(self):
        workflow = self.workflow
        self.assertEqual(set(workflow["on"]), {"workflow_call"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["jobs"]["draft"]["permissions"], {"contents": "write"})
        self.assertNotIn("permissions", workflow["jobs"]["package"])
        self.assertIn("!inputs.dry-run", workflow["jobs"]["package"]["if"])
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow["jobs"]["package"]["if"])
        self.assertNotIn("secrets.", json.dumps(workflow["jobs"]["dry-run"]))
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
        self.assertIn("github.repository", workflow["concurrency"]["group"])
        self.assertIn("inputs.tag", workflow["concurrency"]["group"])

    def test_runner_and_always_cleanup(self):
        self.assertEqual(self.workflow["on"]["workflow_call"]["inputs"]["runner-label"]["default"], "xcode-27")
        package = self.workflow["jobs"]["package"]
        self.assertEqual(package["env"]["XCODE_APP"], "/Applications/Xcode_27.app")
        cleanup_step = next(step for step in package["steps"] if step.get("uses", "").endswith("/cleanup"))
        self.assertEqual(cleanup_step["if"], "${{ always() }}")
        self.assertNotIn("pull_request_target", json.dumps(self.workflow))

    def test_no_expression_interpolation_in_shell(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                self.assertNotIn("${{", step.get("run", ""))


if __name__ == "__main__":
    unittest.main()
