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
            self.assertEqual(len(install_helper.payload(folder)), 5)
            (folder / "service_paths.py").write_text("tampered")
            with self.assertRaises(ValueError):
                install_helper.payload(folder)
            (folder / "service_paths.py").unlink()
            (folder / "service_paths.py").symlink_to(ROOT / "service_paths.py")
            with self.assertRaises(ValueError):
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
