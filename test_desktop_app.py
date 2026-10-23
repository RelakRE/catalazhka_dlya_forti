import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import gui_backend
import install_helper
import privileged_service
import service_client
import service_paths
import split_tunnel as app
import split_tunnel_helper as helper
from test_split_tunnel import FakeOperations, SPEC

ROOT = Path(__file__).resolve().parent
FAKE_WORKER = r'''
import json,sys,select
mode=sys.argv[1]
print(json.dumps({'event':'hello','protocol':2,'uid':0,'mode':mode}),flush=True)
if mode == 'lease':
    spec=json.loads(sys.stdin.readline())
    print(json.dumps({'event':'ready','remaining_seconds':None,'plan':{'seconds':spec['seconds']}}),flush=True)
    sys.stdin.buffer.read(1)
elif mode == 'health':
    print(json.dumps({'event':'ready','remaining_seconds':3}),flush=True)
    sys.stdin.buffer.read(1)
print(json.dumps({'event':'health_complete','ok':True} if mode=='health' else {'event':'rolled_back','rollback':{'ok':True}}),flush=True)
'''


class UnlimitedSessionTests(unittest.TestCase):
    def test_zero_seconds_removes_deadline_but_keeps_eof_and_release(self):
        spec = dict(SPEC, seconds=0)
        helper.validate(spec)
        poll = lambda *args: ([9], [], [])
        self.assertEqual(helper.guard(9, None, object(), clock=lambda: 10**12, poll=poll, reader=lambda *a: b""), "parent_eof")
        self.assertEqual(helper.guard(9, None, object(), clock=lambda: 10**12, poll=poll, reader=lambda *a: b"release"), "release")

    def test_unlimited_session_still_runs_checks_and_detects_long_sleep(self):
        lease = mock.Mock()
        ticks = iter([0, 6, 6])
        polls = iter([([], [], []), ([9], [], [])])
        result = helper.guard(9, None, lease, clock=lambda: next(ticks), poll=lambda *a: next(polls),
                              reader=lambda *a: b"", wall=lambda: 0)
        self.assertEqual(result, "parent_eof")
        lease.check.assert_called_once()
        wall = iter([0, 100])
        with self.assertRaises(helper.base.ProbeError):
            helper.guard(9, None, lease, clock=lambda: 0, poll=lambda *a: ([], [], []), wall=lambda: next(wall))

    def test_config_defaults_to_unlimited(self):
        # Public packages intentionally have no work addresses.
        import profile_store
        value = profile_store.read(ROOT / "split-config.json", allow_empty=True)
        self.assertEqual(value["session_minutes"], 0)

    def test_unlimited_lease_is_rolled_back_like_bounded_lease(self):
        lease = helper.SplitLease(dict(SPEC, seconds=0), FakeOperations())
        lease.begin()
        self.assertTrue(lease.rollback()["ok"])


class CompletionTests(unittest.TestCase):
    def completed(self, **extra):
        return dict(status="complete_rolled_back", session_was_active=True, notes=[], end_event="error",
                    rollback={"event": "rolled_back", "rollback": {"ok": True}}, **extra)

    def test_active_guard_disconnect_is_not_a_gui_failure(self):
        self.assertEqual(app.session_outcome(self.completed(exit_code=2)), "connection_ended")

    def test_sleep_and_network_change_end_without_automatic_reconnect(self):
        for event in ("lease_end", "rolled_back"):
            value = self.completed(exit_code=2)
            value["end_event"] = event
            self.assertEqual(app.session_outcome(value), "connection_ended")

    def test_unconfirmed_rollback_cannot_be_hidden_as_disconnect(self):
        value = self.completed(exit_code=3)
        value["status"] = "rollback_unconfirmed"
        self.assertEqual(app.session_outcome(value), "recovery_required")
        value["status"] = "complete_rolled_back"
        value["rollback"]["rollback"]["ok"] = False
        self.assertEqual(app.session_outcome(value), "failed")

    def test_startup_failure_does_not_become_normal_disconnect(self):
        value = self.completed(exit_code=2)
        value.pop("session_was_active")
        self.assertEqual(app.session_outcome(value), "failed")
        value["session_was_active"] = True
        value["session_failed"] = True
        self.assertEqual(app.session_outcome(value), "failed")

    def test_informational_notes_do_not_turn_disconnect_into_error(self):
        value = self.completed(exit_code=2)
        value["notes"] = ["IPv6 unchanged"]
        self.assertEqual(app.session_outcome(value), "connection_ended")

    def test_manual_stop_is_not_disconnect(self):
        value = self.completed(exit_code=130)
        value.pop("end_event")
        value["notes"] = ["Stopped by user"]
        self.assertEqual(app.session_outcome(value), "stopped")

    def test_cold_launchd_start_retries_only_read_only_status(self):
        expected = "a" * 64
        with mock.patch.object(service_client, "status", side_effect=[{"installed": False},
                {"installed": True, "digest": expected}]) as status, mock.patch.object(service_client, "connect") as connect:
            result = service_client.wait_current(expected, clock=lambda: 0, sleep=lambda _: None)
        self.assertTrue(result["installed"])
        self.assertEqual(status.call_count, 2)
        connect.assert_not_called()

    def test_readiness_deadline_does_not_reinstall_or_authorize(self):
        ticks = iter([0, 21])
        with mock.patch.object(service_client, "status", return_value={"installed": False}), \
             mock.patch.object(service_client, "ServiceGuardian") as guardian:
            with self.assertRaises(helper.base.ProbeError):
                service_client.wait_current("a" * 64, clock=lambda: next(ticks))
        guardian.assert_not_called()

    def test_different_helper_digest_never_accepted(self):
        with mock.patch.object(service_client, "status", return_value={"installed": True, "digest": "old"}):
            with self.assertRaises(helper.base.ProbeError):
                service_client.wait_current("new", timeout=0)

    def test_full_gui_session_reports_guard_disconnect_after_confirmed_rollback(self):
        guardian = mock.Mock()
        guardian.ready.return_value = {"plan": {}}
        guardian.process.returncode = 1  # Actual guard behavior on Forti loss.
        guardian.release.return_value = {"event": "rolled_back", "rollback": {"ok": True}}
        controller = mock.Mock()
        controller.stop_requested.is_set.return_value = False
        def disconnected(guard, control, data, folder):
            data["end_event"] = "error"
            return "VPN disconnected"
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as output, \
             mock.patch.object(app, "OUTPUT", Path(directory)), \
             mock.patch.object(app, "Controller", return_value=controller), \
             mock.patch.object(app, "load_prepared", return_value={}), \
             mock.patch.object(app, "work_connections", return_value={"label": "test", "at": "test", "results": []}), \
             mock.patch.object(app, "make_spec", return_value=(dict(SPEC), [])), \
             mock.patch.object(app.helper.SplitLease, "plan", return_value={"protected_addresses": []}), \
             mock.patch.object(app, "start_guardian", return_value=guardian), \
             mock.patch.object(app, "acceptance", return_value=({"ok": True}, [])), \
             mock.patch.object(app, "wait_session", side_effect=disconnected):
            self.assertEqual(app.session(gui=True), 2)  # CLI diagnostic exit preserved.
            line = output.getvalue().splitlines()[-1]
            self.assertTrue(line.startswith("FORTI_SPLIT_RESULT "))
            result = json.loads(line.removeprefix("FORTI_SPLIT_RESULT "))
            self.assertEqual(result, {"schema": 1, "action": "enable", "pid": os.getpid(), "outcome": "connection_ended"})
            controller.close.assert_called_once()


class ServiceSecurityTests(unittest.TestCase):
    def setUp(self):
        self.server = privileged_service.Server(os.getuid(), ROOT)

    def test_unknown_operations_paths_and_spec_fields_are_rejected(self):
        for request in ({"mode": "shell"}, {"mode": "lease", "path": "/tmp/evil"},
                        {"mode": "health", "spec": SPEC}, {"mode": "lease", "spec": dict(SPEC, command="evil")}):
            with self.subTest(request=request), self.assertRaises((ValueError, KeyError)):
                self.server.validate_request(request)

    def test_work_spec_validated_before_spawning_root_worker(self):
        for address in ("127.0.0.1", "0.0.0.0", "::1", SPEC["gateway"]):
            request = {"mode": "lease", "spec": dict(SPEC, work_addresses=[address])}
            with self.assertRaises((ValueError, helper.base.ProbeError)):
                self.server.validate_request(request)

    def test_worker_is_isolated_and_cannot_choose_executable(self):
        argv = service_paths.worker_argv("/protected/path", "lease")
        self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-c"])
        self.assertEqual(argv[-1], "lease")
        with self.assertRaises(ValueError):
            service_paths.worker_argv("/protected/path", "sh")

    def test_peer_credentials_are_real_current_uid(self):
        left, right = socket.socketpair()
        try:
            self.assertEqual(service_paths.peer_uid(left), os.getuid())
        finally:
            left.close(); right.close()

    def test_wrong_peer_never_starts_process(self):
        left, right = socket.socketpair()
        with mock.patch.object(service_paths, "peer_uid", return_value=os.getuid() + 1), \
             mock.patch.object(privileged_service.subprocess, "Popen") as start:
            self.server.handle(right)
            value = json.loads(left.recv(4096))
            self.assertEqual(value["event"], "error")
            start.assert_not_called()
        left.close()

    def test_existing_foreign_socket_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PermissionError):
                service_paths.check_root_directory(Path(directory))

    def test_installer_manifest_blocks_tampering_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name in service_paths.ROOT_MODULES:
                (folder / name).write_bytes((ROOT / name).read_bytes())
            (folder / "helper-manifest.json").write_text(json.dumps({"api": 1, "digest": service_paths.digest(folder)}))
            self.assertEqual(len(install_helper.payload(folder)), len(service_paths.ROOT_MODULES) + 1)
            (folder / "service_paths.py").write_text("tampered")
            with self.assertRaises((ValueError, OSError)):
                install_helper.payload(folder)
            (folder / "service_paths.py").unlink()
            (folder / "service_paths.py").symlink_to(ROOT / "service_paths.py")
            with self.assertRaises((ValueError, OSError)):
                install_helper.payload(folder)

    def test_launchd_uses_root_protected_copy_and_never_sudoers(self):
        value = install_helper.service_plist(501)
        self.assertEqual(value["UserName"], "root")
        self.assertIn("/Library/PrivilegedHelperTools/local.fortisplit.helper/501", " ".join(value["ProgramArguments"]))
        self.assertNotIn(str(ROOT), " ".join(value["ProgramArguments"]))
        self.assertNotIn("sudo", json.dumps(value))

    def test_nonroot_installer_fails_before_opening_system_journal(self):
        with mock.patch.object(sys, "argv", ["installer", "--source", str(ROOT), "--uid", "501"]), \
             mock.patch.object(install_helper.os, "geteuid", return_value=501), \
             mock.patch.object(install_helper.os, "open") as opened:
            with self.assertRaises(PermissionError):
                install_helper.main()
        opened.assert_not_called()

    def test_gui_stdin_eof_requests_orderly_backend_shutdown(self):
        from types import SimpleNamespace
        import signal
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(gui_backend.sys, "stdin", SimpleNamespace(fileno=lambda: read_fd)), \
                 mock.patch.object(gui_backend.os, "kill") as kill:
                thread = threading.Thread(target=gui_backend.watch_gui)
                thread.start()
                os.close(write_fd)
                write_fd = None
                thread.join(2)
                self.assertFalse(thread.is_alive())
                kill.assert_called_once_with(os.getpid(), signal.SIGTERM)
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)


class ServiceIntegrationTests(unittest.TestCase):
    def run_worker(self, mode):
        left, right = socket.socketpair()
        server = privileged_service.Server(os.getuid(), ROOT)
        patch = mock.patch.object(service_paths, "worker_argv", side_effect=lambda path, mode: [sys.executable, "-u", "-c", FAKE_WORKER, mode])
        patch.start()
        thread = threading.Thread(target=server.handle, args=(right,))
        thread.start()
        return left, server, patch, thread

    def test_real_socket_and_subprocess_handshake_release_for_all_modes(self):
        for mode in ("lease", "health", "recover"):
            with self.subTest(mode=mode):
                conn, server, patch, thread = self.run_worker(mode)
                try:
                    events = []
                    with mock.patch.object(service_client, "connect", return_value=conn):
                        guardian = service_client.ServiceGuardian(dict(SPEC, seconds=0) if mode == "lease" else None, events, mode)
                    if mode != "recover":
                        guardian.ready()
                    final = guardian.release()
                    self.assertEqual(final["event"], "health_complete" if mode == "health" else "rolled_back")
                    self.assertEqual(guardian.process.returncode, 0)
                    thread.join(5)
                    self.assertFalse(thread.is_alive())
                    self.assertFalse(server.busy)
                finally:
                    conn.close(); thread.join(5); patch.stop()

    def test_gui_crash_eof_releases_worker_without_root_or_network_mutation(self):
        conn, server, patch, thread = self.run_worker("lease")
        try:
            with mock.patch.object(service_client, "connect", return_value=conn):
                guardian = service_client.ServiceGuardian(dict(SPEC, seconds=0), [])
            guardian.ready()
            guardian.conn.close()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(server.busy)
        finally:
            conn.close(); thread.join(5); patch.stop()

    def test_uninstall_does_not_remove_unknown_files_or_workspace(self):
        # No installer root entrypoint is called in tests.
        self.assertEqual(install_helper.BASE, Path("/Library/PrivilegedHelperTools/local.fortisplit.helper"))
        self.assertNotIn("rmtree", (ROOT / "install_helper.py").read_text())

    def test_backend_reports_status_without_sudo_or_mutation(self):
        with mock.patch.object(service_client, "status", return_value={"installed": False}), \
             mock.patch.object(gui_backend.helper.Operations, "forti", return_value=None), \
             mock.patch.object(app, "load_prepared", side_effect=ValueError("not prepared")), \
             mock.patch.object(app, "request_control", return_value=None):
            state = gui_backend.state()
        self.assertFalse(state["service"]["installed"])
        self.assertFalse(state["prepared"])


if __name__ == "__main__":
    unittest.main()
