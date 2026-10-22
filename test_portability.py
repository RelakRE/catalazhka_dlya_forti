import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import desktop_entry
import gui_backend
import json_codec
import platform_contract
import profile_model
import profile_store
import service_client
import service_paths
import setup_flow
import split_tunnel as app
import privileged_service
from test_split_tunnel import FakeOperations, SPEC


class PortableContractTests(unittest.TestCase):
    def test_platform_matrix_is_explicit_and_fail_closed(self):
        for system, cpu, version, expected in (
            ("Darwin", "x86_64", "13.0", True), ("Darwin", "x86_64", "14.8.9", True),
            ("Darwin", "x86_64", "12.7", False), ("Darwin", "arm64", "15.0", False),
            ("Darwin", "x86_64", "unknown", False), ("Windows", "AMD64", "11", False),
            ("Linux", "x86_64", "", False),
        ):
            with self.subTest(system=system, cpu=cpu, version=version):
                self.assertEqual(platform_contract.describe(system, cpu, version).supported, expected)

    def test_windows_entrypoint_does_not_import_or_call_macos_backend(self):
        info = platform_contract.describe("Windows", "AMD64", "11")
        output = io.StringIO()
        with mock.patch.object(desktop_entry, "describe", return_value=info), \
             mock.patch.dict("sys.modules", {"gui_backend": None}), contextlib.redirect_stdout(output):
            self.assertEqual(desktop_entry.main(["status"]), 2)
        value = json.loads(output.getvalue())
        self.assertFalse(value["platform"]["supported"])
        self.assertIn("Windows", value["status_error"])

    def test_profile_accepts_utf8_bom_from_windows_editors(self):
        value = {"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20"]}
        self.assertEqual(profile_model.parse("\ufeff" + json.dumps(value)), value)

    def test_ambiguous_nonstandard_or_deep_json_is_rejected(self):
        for text in ('{"schema":1,"schema":2}', '{"value":NaN}', '{"value":Infinity}', '[' * 3000 + ']' * 3000):
            with self.subTest(text=text[:50]), self.assertRaises(ValueError):
                json_codec.loads(text)

    def test_profile_file_names_can_be_unicode_and_contain_spaces(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Рабочий профиль коллеги.json"
            value = {"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20"]}
            profile_store.save(path, value)
            self.assertEqual(profile_store.read(path), value)

    def test_user_data_directory_is_private_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "data"
            directory.mkdir(mode=0o755)
            profile_store.secure_directory(directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            linked = Path(folder) / "linked"
            linked.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(PermissionError):
                profile_store.secure_directory(linked)


class WizardTests(unittest.TestCase):
    def setUp(self):
        self.value = {"profile": {"ready": False}, "service": {"installed": False}, "session": None}

    def stage(self):
        return setup_flow.flow(self.value)["stage"]

    def test_first_connection_has_ordered_single_primary_steps(self):
        self.assertEqual(self.stage(), "profile")
        self.value["profile"]["ready"] = True
        self.assertEqual(self.stage(), "access")
        self.value["service"] = {"installed": True, "current": True}
        self.assertEqual(self.stage(), "health")
        self.value["helper_healthy"] = True
        self.assertEqual(self.stage(), "network")
        self.value["prepared"] = True
        self.assertEqual(self.stage(), "connect")
        self.value["vpn"] = {"interface": "utun2"}
        self.assertEqual(self.stage(), "ready")
        self.assertEqual(setup_flow.flow(self.value)["action"], "enable")
        self.assertNotIn("30", setup_flow.flow(self.value)["detail"])
        self.assertNotIn("минут", setup_flow.flow(self.value)["detail"])

    def test_no_unsafe_enable_when_unprepared_or_in_another_session(self):
        self.value.update(profile={"ready": True}, service={"installed": True, "current": True}, helper_healthy=True,
                          vpn={"interface": "utun2"})
        self.assertEqual(self.stage(), "disconnect")
        self.assertEqual(setup_flow.flow(self.value)["action"], "open-forti")
        self.value["prepared"] = True
        self.value["session"] = {"state": "active"}
        self.assertTrue(setup_flow.flow(self.value)["blocked"])

    def test_vpn_errors_are_visible_and_recovery_has_priority(self):
        self.value.update(profile={"ready": True}, service={"installed": True, "current": True}, helper_healthy=True,
                          vpn_error="other VPN")
        self.assertEqual(self.stage(), "vpn_error")
        self.value["latest_status"] = "rollback_unconfirmed"
        self.assertEqual(self.stage(), "recovery")

    def test_missing_client_is_detected_before_installing_root_service(self):
        self.value.update(profile={"ready": True}, preflight={"forticlient_available": False})
        self.assertEqual(self.stage(), "missing_forti")
        self.assertNotEqual(setup_flow.flow(self.value)["action"], "install")

    def test_unsupported_system_never_offers_privilege_or_routes(self):
        self.value["platform"] = platform_contract.describe("Windows", "AMD64", "11").json()
        self.assertEqual(self.stage(), "unsupported")
        self.assertTrue(setup_flow.flow(self.value)["blocked"])


class ReliabilityTests(unittest.TestCase):
    def test_installer_reads_relative_descriptors_not_source_symlinks(self):
        import install_helper
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            nested = root / "nested"
            nested.mkdir()
            (nested / "code.py").write_bytes(b"safe")
            self.assertEqual(install_helper.read_source(root, "nested/code.py", 4), b"safe")
            with self.assertRaises(ValueError):
                install_helper.read_source(root, "nested/code.py", 3)
            linked = root / "link"
            linked.symlink_to(nested, target_is_directory=True)
            with self.assertRaises(OSError):
                install_helper.read_source(root, "link/code.py", 4)
            with self.assertRaises(ValueError):
                install_helper.read_source(root, "../outside", 10)

    def test_failed_atomic_profile_replacement_preserves_old_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "profile.json"
            old = {"schema": 1, "session_minutes": 0, "work_ipv4": ["10.77.1.20"]}
            new = dict(old, work_ipv4=["10.77.1.21"])
            profile_store.save(path, old)
            with mock.patch.object(profile_store.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    profile_store.save(path, new)
            self.assertEqual(profile_store.read(path), old)
            self.assertEqual(list(Path(folder).iterdir()), [path])

    def test_successful_recovery_supersedes_older_failed_session_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, status, ok in (("split-session-20261022-120000-000001", "rollback_unconfirmed", False),
                                     ("split-recovery-20261022-120001-000001", "recovered", True)):
                target = root / name
                target.mkdir()
                profile_store.save(target / "report.json", {"status": status, "rollback": {"rollback": {"ok": ok}}})
            with mock.patch.object(app, "OUTPUT", root), \
                 mock.patch.object(service_client, "status", return_value={"installed": False}), \
                 mock.patch.object(gui_backend.helper.Operations, "forti", return_value=None), \
                 mock.patch.object(app, "load_prepared", side_effect=ValueError("no preparation")), \
                 mock.patch.object(app, "request_control", return_value=None):
                state = gui_backend.state()
            self.assertEqual(state["latest_status"], "recovered")
            self.assertTrue(state["rollback_ok"])

    def test_dead_telemetry_pipe_does_not_prevent_existing_route_rollback(self):
        import route_probe_helper
        import split_tunnel_helper
        ops = FakeOperations()
        lease = split_tunnel_helper.SplitLease(copy.deepcopy(SPEC), ops, observer=route_probe_helper.emit)
        with mock.patch("builtins.print", side_effect=BrokenPipeError("UI is gone")):
            lease.begin()
            self.assertTrue(lease.rollback()["ok"])
        self.assertFalse(lease.entries)

    def test_health_marker_is_bound_to_current_helper_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "split-config.json"
            service = {"installed": True, "current": True, "digest": "a" * 64}
            with mock.patch.object(app, "CONFIG", config):
                self.assertFalse(gui_backend.helper_healthy(service))
                profile_store.save(gui_backend.health_path(), {"ok": True, "digest": service["digest"]})
                self.assertTrue(gui_backend.helper_healthy(service))
                self.assertFalse(gui_backend.helper_healthy(dict(service, digest="b" * 64)))
                self.assertFalse(gui_backend.helper_healthy(dict(service, current=False)))

    def test_malformed_helper_status_is_unavailable_not_a_crash(self):
        for raw in (b'[]\n', b'{"api":true}\n', b'{"api":1,"api":1}\n'):
            left, right = socket.socketpair()
            def reply():
                with right:
                    right.recv(4096)
                    right.sendall(raw)
            thread = threading.Thread(target=reply)
            thread.start()
            with mock.patch.object(service_client, "connect", return_value=left):
                self.assertFalse(service_client.status()["installed"])
            thread.join(2)

    def test_duplicate_keys_never_spawn_privileged_worker(self):
        root = Path(__file__).resolve().parent
        left, right = socket.socketpair()
        try:
            left.sendall(b'{"mode":"health","mode":"lease"}\n')
            server = privileged_service.Server(os.getuid(), root)
            with mock.patch.object(service_paths, "peer_uid", return_value=os.getuid()), \
                 mock.patch.object(privileged_service.subprocess, "Popen") as start:
                server.handle(right)
                self.assertEqual(json.loads(left.recv(4096))["event"], "error")
                start.assert_not_called()
        finally:
            left.close()

    def test_slow_drip_handshake_has_absolute_deadline(self):
        client = mock.Mock()
        client.recv.return_value = b" "
        server = privileged_service.Server(os.getuid(), Path(__file__).resolve().parent)
        with mock.patch.object(service_paths, "peer_uid", return_value=os.getuid()), \
             mock.patch.object(privileged_service.time, "monotonic", side_effect=[0, 1, 6]), \
             mock.patch.object(privileged_service.subprocess, "Popen") as start:
            server.handle(client)
            start.assert_not_called()
            self.assertIn("deadline", client.sendall.call_args[0][0].decode())

    def test_busy_flag_is_held_until_background_rollback_reaps(self):
        server = privileged_service.Server(os.getuid(), Path(__file__).resolve().parent)
        server.busy = True
        worker = mock.Mock()
        worker.poll.return_value = 0
        worker.communicate.side_effect = lambda: self.assertTrue(server.busy)
        server.reap_busy(worker)
        self.assertFalse(server.busy)


if __name__ == "__main__":
    unittest.main()
