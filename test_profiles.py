import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import subprocess
import unittest
from unittest import mock

import bundle_runtime
import gui_backend
import install_helper
import profile_store
import service_paths
import split_tunnel

PROFILE = {"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20", "10.77.1.53"]}


class ProfileTests(unittest.TestCase):
    def test_valid_profile_is_canonical_and_unlimited(self):
        self.assertEqual(profile_store.parse(json.dumps(PROFILE)), PROFILE)

    def test_empty_template_is_not_a_working_profile(self):
        value = dict(PROFILE, work_ipv4=[])
        with self.assertRaises(ValueError):
            profile_store.parse(json.dumps(value))
        self.assertEqual(profile_store.parse(json.dumps(value), allow_empty=True), value)

    def test_invalid_and_command_fields_are_rejected(self):
        variants = [dict(PROFILE, schema=True), dict(PROFILE, schema=2), dict(PROFILE, password="secret"),
                    dict(PROFILE, session_minutes=True), dict(PROFILE, session_minutes=-1),
                    dict(PROFILE, session_minutes=481), dict(PROFILE, work_ipv4="10.77.1.20")]
        for address in ("0.0.0.0", "127.0.0.1", "169.254.1.1", "224.1.1.1", "::1", "10.0.0.0/8", "$(id)", 123):
            variants.append(dict(PROFILE, work_ipv4=[address]))
        variants += [dict(PROFILE, work_ipv4=["10.77.1.20"] * 2), dict(PROFILE, work_ipv4=["10.77.1.20"] * 129)]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                profile_store.parse(json.dumps(value))

    def test_save_is_private_and_invalid_import_leaves_old_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "profile.json"
            profile_store.save(path, PROFILE)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(profile_store.read(path), PROFILE)
            link = Path(folder) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                profile_store.read(link)
            large = Path(folder) / "large.json"
            large.write_bytes(b" " * (profile_store.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                profile_store.read(large)
            self.assertEqual(profile_store.read(path), PROFILE)

    def test_import_invalidates_preparation_and_blocks_active_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            incoming = root / "incoming.json"
            profile_store.save(incoming, PROFILE)
            argv = ["gui_backend.py", "--data-root", folder, "import-profile", "--profile", str(incoming)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(split_tunnel, "request_control", return_value=None), \
                 mock.patch.object(gui_backend.service_client, "status", return_value={}), \
                 mock.patch.multiple(split_tunnel, OUTPUT=root, PREPARED=root / "prepared.json", CONFIG=root / "config.json"), \
                 mock.patch.object(gui_backend, "configure"), mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(gui_backend.main(), 0)
                self.assertEqual(profile_store.read(split_tunnel.CONFIG), PROFILE)
                self.assertEqual(json.loads(split_tunnel.PREPARED.read_text()), {"ready": False})
                split_tunnel.PREPARED.write_text('{"ready": true}')
                with mock.patch.object(split_tunnel, "request_control", return_value={"state": "active"}):
                    self.assertEqual(gui_backend.main(), 2)
                self.assertTrue(json.loads(split_tunnel.PREPARED.read_text())["ready"])
                incoming.write_text('{"schema": 2}')
                self.assertEqual(gui_backend.main(), 2)
                self.assertEqual(profile_store.read(split_tunnel.CONFIG), PROFILE)


class RuntimeTests(unittest.TestCase):
    def test_compaction_removes_only_identical_aliases(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bin").mkdir()
            for name in ("python", "python3", "python3.12"):
                (root / "bin" / name).write_bytes(b"same interpreter")
            stdlib = root / "stdlib.py"
            stdlib.write_bytes(b"unchanged")
            result = bundle_runtime.compact(root)
            self.assertEqual(result["saved_bytes"], 2 * len(b"same interpreter"))
            self.assertTrue((root / "bin/python3.12").is_file())
            self.assertEqual(stdlib.read_bytes(), b"unchanged")
            self.assertFalse((root / "bin/python").exists())

    def test_compaction_rejects_nonidentical_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bin").mkdir()
            (root / "bin/python3.12").write_bytes(b"canonical")
            (root / "bin/python").write_bytes(b"different")
            with self.assertRaises(ValueError):
                bundle_runtime.compact(root)
            self.assertEqual((root / "bin/python").read_bytes(), b"different")

    def test_archive_traversal_and_devices_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("python/../../escape", "/python/bin/test", "other/bin/test"):
                archive = root / "archive.tar.gz"
                with tarfile.open(archive, "w:gz") as out:
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    out.addfile(info, io.BytesIO(b"x"))
                with self.assertRaises(ValueError):
                    bundle_runtime.extract(archive, root / "result")
            self.assertFalse((root / "escape").exists())

    def test_runtime_manifest_tampering_and_linked_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in service_paths.ROOT_MODULES:
                (root / name).write_text("# test\n")
            executable = root / "runtime/bin/python3.12"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"interpreter fixture")
            executable.chmod(0o755)
            manifest = bundle_runtime.manifest(root / "runtime")
            (root / "runtime-manifest.json").write_text(json.dumps(manifest))
            original_digest = service_paths.digest(root)
            (root / "helper-manifest.json").write_text(json.dumps({"api": 1, "digest": original_digest}))
            self.assertIn("runtime/bin/python3.12", install_helper.payload(root))
            self.assertEqual(service_paths.worker_argv(root, "health")[0], str(executable))
            self.assertTrue(install_helper.service_plist(501, True)["ProgramArguments"][0].endswith("runtime/bin/python3.12"))
            executable.write_bytes(b"tamper")
            with self.assertRaises((ValueError, OSError)):
                install_helper.payload(root)
            executable.unlink()
            executable.symlink_to(root / "service_paths.py")
            with self.assertRaises((ValueError, OSError)):
                install_helper.payload(root)

    def test_unsafe_runtime_manifest_paths_are_rejected(self):
        base = {"sha256": hashlib.sha256(b"x").hexdigest(), "size": 1, "executable": True}
        for name in ("../escape", "/absolute", "a/../b", "a//b", "./bin/extra"):
            value = {"schema": 1, "files": {"bin/python3.12": base, name: base}}
            with self.assertRaises(ValueError):
                install_helper.runtime_listing(json.dumps(value))


class InstallTransactionTests(unittest.TestCase):
    def transaction(self, fail=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            base = root / "helpers"
            base.mkdir()
            installed = base / "501"
            installed.mkdir()
            (installed / "service_paths.py").write_bytes(b"old-version")
            plist = root / "helper.plist"
            plist.write_bytes(b"old-registration")
            original = Path.lstat

            def root_stat(path):
                data = list(original(path))
                data[4] = 0  # Simulate protected root-owned temp files, no real chown.
                return os.stat_result(data)

            calls = []
            def launch(*arguments):
                calls.append(arguments)
                if fail and len(calls) == 2:
                    raise subprocess.CalledProcessError(1, "bootstrap")

            def directory(path):
                path.mkdir(parents=False, exist_ok=True)

            with mock.patch.object(install_helper, "BASE", base), \
                 mock.patch.object(install_helper, "protected_directory", side_effect=directory), \
                 mock.patch.object(Path, "lstat", root_stat), \
                 mock.patch.object(install_helper, "launch", side_effect=launch), \
                 mock.patch.object(install_helper.subprocess, "run", return_value=mock.Mock(returncode=1)):
                files = {"service_paths.py": b"new-version"}
                if fail:
                    with self.assertRaises(RuntimeError):
                        install_helper.install_transaction(501, files, plist, True)
                    self.assertEqual((installed / "service_paths.py").read_bytes(), b"old-version")
                    self.assertEqual(plist.read_bytes(), b"old-registration")
                    self.assertEqual(calls[-1], ("bootstrap", "system", str(plist)))
                else:
                    install_helper.install_transaction(501, files, plist, True)
                    self.assertEqual((installed / "service_paths.py").read_bytes(), b"new-version")
                    self.assertEqual(len(calls), 2)
                    self.assertFalse(list(base.glob(".501-install-*")))

    def test_complete_upgrade_and_known_old_copy_cleanup(self):
        self.transaction()

    def test_failed_registration_restores_old_code_and_registration(self):
        self.transaction(fail=True)


if __name__ == "__main__":
    unittest.main()
