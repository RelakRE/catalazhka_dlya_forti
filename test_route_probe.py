import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import route_probe as probe
import route_probe_helper as helper


SPEC = {"target": "1.1.1.1", "gateway": "192.168.88.1", "source": "192.168.88.102",
        "interface": "en0", "vpn_interface": "utun6"}


class FakeOperations:
    def __init__(self):
        self.entries = [{"destination": SPEC["target"], "gateway": "link#28",
                         "flags": "UHWIig", "interface": "utun6"}]
        self.mutations = []
        self.changed_gateway = False
        self.fail_after_add = False
        self.force_vpn = False
        self.refuse_delete = False

    def forti(self):
        return {"interface": "utun6", "server": "8.8.8.8"}

    def physical(self, interface, gateway, source):
        if self.changed_gateway:
            raise helper.ProbeError("gateway changed")
        return {"interface": interface, "gateway": gateway, "source": source}

    def route(self, target):
        own = helper.owned_rows(self.entries, SPEC)
        if own and not self.force_vpn:
            return {"destination": target, "gateway": SPEC["gateway"], "interface": "en0", "flags": []}
        return {"destination": "default", "interface": "utun6", "flags": []}

    def rows(self, target):
        return list(self.entries)

    def run(self, argv):
        self.mutations.append(argv)
        if argv[2] == "add":
            self.entries.append({"destination": SPEC["target"], "gateway": SPEC["gateway"],
                                 "flags": "UGHS", "interface": "en0"})
            if self.fail_after_add:
                raise helper.ProbeError("timeout after kernel accepted add")
        elif "-ifscope" in argv:
            self.entries = [row for row in self.entries if row["interface"] != "utun6"]
        elif not self.refuse_delete:
            self.entries = [row for row in self.entries if not helper.owned_rows([row], SPEC)]
        return "fixture route response"


class RouteLeaseTests(unittest.TestCase):
    def lease(self, ops):
        self.journal = []
        return helper.RouteLease(dict(SPEC), ops=ops, journal=self.journal.append)

    def test_scoped_cache_is_removed_but_only_one_host_route_is_added_and_rolled_back(self):
        ops = FakeOperations()
        lease = self.lease(ops)
        ready = lease.begin()
        self.assertEqual(ready["effective"]["interface"], "en0")
        restored = lease.rollback()
        self.assertTrue(restored["ok"])
        self.assertEqual(restored["effective"]["interface"], "utun6")
        self.assertEqual(ops.mutations, [
            ["/sbin/route", "-n", "delete", "-host", "-ifscope", "utun6", SPEC["target"]],
            ["/sbin/route", "-n", "add", "-host", SPEC["target"], SPEC["gateway"]],
            ["/sbin/route", "-n", "delete", "-host", SPEC["target"], SPEC["gateway"]]])
        self.assertEqual(self.journal[-1], {"status": "inactive"})
        self.assertTrue(lease.rollback()["ok"])
        self.assertEqual(len(ops.mutations), 3)

    def test_static_or_noncache_existing_route_is_never_overwritten(self):
        for flags in ("UGHS", "UGHSi", "UGHI", "UHLWI"):
            ops = FakeOperations()
            ops.entries[0]["flags"] = flags
            if "W" in flags and "S" not in flags:
                continue
            with self.assertRaises(helper.ProbeError):
                self.lease(ops).begin()
            self.assertFalse(ops.mutations)

    def test_gateway_change_prevents_every_mutation(self):
        ops = FakeOperations()
        ops.changed_gateway = True
        with self.assertRaises(helper.ProbeError):
            self.lease(ops).begin()
        self.assertFalse(ops.mutations)

    def test_private_loopback_and_ipv6_destinations_are_rejected(self):
        for address in ("10.0.0.3", "127.0.0.1", "0.0.0.0", "::1", "192.168.88.1"):
            with self.assertRaises((helper.ProbeError, ValueError)):
                helper.RouteLease(dict(SPEC, target=address))

    def test_wrong_vpn_or_transport_address_prevents_mutations(self):
        for context in ({"interface": "utun7", "server": "8.8.8.8"},
                        {"interface": "utun6", "server": SPEC["target"]}):
            ops = FakeOperations()
            ops.forti = lambda: context
            with self.assertRaises(helper.ProbeError):
                self.lease(ops).begin()
            self.assertFalse(ops.mutations)

    def test_add_timeout_after_kernel_mutation_is_still_rolled_back(self):
        ops = FakeOperations()
        ops.fail_after_add = True
        lease = self.lease(ops)
        with self.assertRaises(helper.ProbeError):
            lease.begin()
        self.assertTrue(lease.armed)
        self.assertTrue(lease.rollback()["ok"])
        self.assertFalse(helper.owned_rows(ops.entries, SPEC))

    def test_enforced_vpn_path_causes_abort_and_removes_hidden_physical_route(self):
        ops = FakeOperations()
        ops.force_vpn = True
        lease = self.lease(ops)
        with self.assertRaises(helper.ProbeError):
            lease.begin()
        self.assertTrue(helper.owned_rows(ops.entries, SPEC))
        self.assertTrue(lease.rollback()["ok"])
        self.assertFalse(helper.owned_rows(ops.entries, SPEC))

    def test_foreign_replacement_is_preserved_and_journal_not_cleared(self):
        ops = FakeOperations()
        lease = self.lease(ops)
        lease.begin()
        ops.entries = [{"destination": SPEC["target"], "gateway": "192.168.88.254",
                        "interface": "en0", "flags": "UGHS"}]
        count = len(ops.mutations)
        self.assertFalse(lease.rollback()["ok"])
        self.assertEqual(len(ops.mutations), count)
        self.assertEqual(self.journal[-1]["status"], "armed")

    def test_failed_delete_never_claims_success(self):
        ops = FakeOperations()
        lease = self.lease(ops)
        lease.begin()
        ops.refuse_delete = True
        self.assertFalse(lease.rollback()["ok"])
        self.assertTrue(lease.armed)

    def test_route_and_table_parsers_preserve_scope_and_flags(self):
        parsed = helper.parse_route("destination: default\n  interface: utun6\n"
                                    "flags: <UP,HOST,WASCLONED,IFSCOPE>\n")
        self.assertIn("WASCLONED", parsed["flags"])
        raw = "default link#28 UCSg utun6\n1.1.1.1 192.168.88.1 UGHS en0\n" \
              "1.1.1.1 link#28 UHWIig utun6\n93.184.216.35 1.2.3.4 UGHS en0\n"
        self.assertEqual(len(helper.route_rows(raw, SPEC["target"])), 2)
        self.assertEqual(len(helper.owned_rows(helper.route_rows(raw, SPEC["target"]), SPEC)), 1)

    def test_guardian_finishes_on_eof_release_or_deadline(self):
        poll = lambda *args: ([123], [], [])
        self.assertEqual(helper.wait_for_release(123, 45, clock=lambda: 0,
                                                poll=poll, reader=lambda *args: b""), "parent_eof")
        self.assertEqual(helper.wait_for_release(123, 45, clock=lambda: 0,
                                                poll=poll, reader=lambda *args: b"release\n"), "release")
        self.assertEqual(helper.wait_for_release(123, 45, clock=lambda: 46), "deadline")

    def test_helper_main_rolls_back_for_deadline_and_wait_error(self):
        for failure in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                ops = FakeOperations()
                journal_path = Path(directory) / "journal"
                fd = os.open(str(journal_path), os.O_RDWR | os.O_CREAT, 0o600)
                argv = ["route_probe_helper.py", "lease"]
                for key, value in SPEC.items():
                    argv += ["--" + key.replace("_", "-"), value]
                def wait(*args):
                    if failure:
                        raise helper.ProbeError("simulated signal/wait failure")
                    return "deadline"
                with mock.patch.object(helper.os, "geteuid", return_value=0), \
                        mock.patch.object(helper, "acquire_journal", return_value=(fd, {"status": "inactive"})), \
                        mock.patch.object(helper, "Operations", return_value=ops), \
                        mock.patch.object(helper, "wait_for_release", side_effect=wait), \
                        mock.patch.object(helper.signal, "signal"), \
                        mock.patch.object(helper.sys, "argv", argv), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(helper.main(), 1 if failure else 0)
                events = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(events[-1]["event"], "rolled_back")
                self.assertTrue(events[-1]["rollback"]["ok"])
                self.assertFalse(helper.owned_rows(ops.entries, SPEC))
                self.assertEqual(json.loads(journal_path.read_text())["status"], "inactive")

    def test_parent_guardian_protocol_reads_buffered_events_without_sudo(self):
        real_popen = subprocess.Popen
        program = "import sys,json,os; print(json.dumps({'event':'hello','protocol':2,'mode':'lease','uid':0}),flush=True); " \
                  "print(json.dumps({'event':'ready','remaining_seconds':44,'session_id':os.getsid(0)}),flush=True); " \
                  "sys.stdin.readline(); print(json.dumps({'event':'lease_end','reason':'release'}),flush=True); " \
                  "print(json.dumps({'event':'rolled_back','rollback':{'ok':True}}),flush=True)"
        def unprivileged_process(argv, **kwargs):
            self.assertFalse(kwargs["start_new_session"])
            return real_popen(["/usr/bin/python3", "-u", "-c", program], **kwargs)
        events = []
        with mock.patch.object(probe.subprocess, "Popen", side_effect=unprivileged_process):
            guardian = probe.Guardian(SPEC, events)
            ready = guardian.ready()
            self.assertEqual(ready["event"], "ready")
            self.assertEqual(ready["session_id"], os.getsid(0))
            self.assertTrue(guardian.release()["rollback"]["ok"])
            guardian.process.stdout.close()
        self.assertEqual([event["event"] for event in events], ["hello", "ready", "lease_end", "rolled_back"])

    def test_interrupted_parent_still_requests_rollback_and_saves_report(self):
        class FakeGuardian:
            def __init__(self, spec, events):
                self.events = events
            def ready(self):
                raise KeyboardInterrupt()
            def release(self):
                return {"event": "rolled_back", "rollback": {"ok": True}}
        fake_result = {"name": "test", "argv": ["mock"], "exit_code": 0,
                       "timeout": False, "seconds": 0, "output": "fixture"}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(probe, "OUTPUT", Path(directory)), \
                mock.patch.object(probe, "load_prepared", return_value={"protected_addresses": []}), \
                mock.patch.object(probe, "preflight", return_value=SPEC), \
                mock.patch.object(probe, "authenticate_sudo", return_value={"exit_code": 0}), \
                mock.patch.object(probe.diag, "batch", return_value=[]), \
                mock.patch.object(probe.diag, "command", return_value=fake_result), \
                mock.patch.object(probe.diag, "app_connections", return_value={"results": []}), \
                mock.patch.object(probe, "Guardian", FakeGuardian), \
                mock.patch.object(probe.signal, "signal"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.probe(True), 130)
            report = next(Path(directory).glob("route-probe-*/report.json"))
            data = json.loads(report.read_text())
            self.assertTrue(data["rollback_confirmed"])
            self.assertEqual(data["status"], "stopped_rolled_back")

    def test_known_sudo_errors_preserved_but_credential_values_still_redacted(self):
        self.assertEqual(probe.launch_output("sudo: a password is required\n"), "sudo: a password is required")
        self.assertEqual(probe.launch_output("sudo: 1 incorrect password attempt"), "sudo: 1 incorrect password attempt")
        self.assertNotIn("never-log-this", probe.launch_output("sudo: password=never-log-this"))
        self.assertNotIn("never-log-this", probe.launch_output("cookie: never-log-this"))

    def test_authentication_failure_without_newline_is_recorded_as_not_started(self):
        real_popen = subprocess.Popen
        program = "import sys; sys.stderr.write('sudo: a password is required'); sys.exit(1)"
        def unprivileged_process(argv, **kwargs):
            return real_popen(["/usr/bin/python3", "-u", "-c", program], **kwargs)
        events = []
        with mock.patch.object(probe.subprocess, "Popen", side_effect=unprivileged_process):
            guardian = probe.Guardian(SPEC, events)
            with self.assertRaises(probe.HelperNotStarted):
                guardian.ready()
            final = guardian.release()
        self.assertEqual(final["event"], "not_started")
        self.assertFalse(final["network_changes"])
        self.assertEqual(events[0]["text"], "sudo: a password is required")
        self.assertFalse(events[-1]["helper_started"])
        self.assertEqual(events[-1]["exit_code"], 1)

    def test_health_helper_does_not_open_journal_or_instantiate_route_operations(self):
        with mock.patch.object(helper.os, "geteuid", return_value=0), \
                mock.patch.object(helper, "acquire_journal") as journal, \
                mock.patch.object(helper, "Operations") as operations, \
                mock.patch.object(helper, "RouteLease") as lease, \
                mock.patch.object(helper, "execute") as execute, \
                mock.patch.object(helper, "wait_for_release", return_value="parent_eof"), \
                mock.patch.object(helper.signal, "signal"), \
                mock.patch.object(helper.sys, "argv", ["helper", "health"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(helper.main(), 0)
        for unused in (journal, operations, lease, execute):
            unused.assert_not_called()
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([event["event"] for event in events], ["hello", "ready", "health_complete"])
        self.assertFalse(events[-1]["network_changes"])

    def test_self_test_runs_real_pipe_eof_and_deadline_without_actual_root_or_sudo(self):
        real_popen = subprocess.Popen
        # Only UID reporting is simulated. The actual health implementation runs
        # in ordinary child processes and may never invoke journal/route code.
        program = "import sys,route_probe_helper as h; h.os.geteuid=lambda:0; " \
                  "sys.argv=['helper','health']; sys.exit(h.main())"
        def unprivileged_process(argv, **kwargs):
            self.assertFalse(kwargs["start_new_session"])
            self.assertIn("health", argv)
            return real_popen(["/usr/bin/python3", "-u", "-c", program], **kwargs)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(probe, "OUTPUT", Path(directory)), \
                mock.patch.object(probe, "authenticate_sudo", return_value={"exit_code": 0}), \
                mock.patch.object(probe.subprocess, "Popen", side_effect=unprivileged_process), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = probe.self_test()
            self.assertEqual(code, 0, output.getvalue())
            data = json.loads(next(Path(directory).glob("helper-health-*/report.json")).read_text())
        self.assertEqual(data["result"], "helper_health_passed")
        self.assertFalse(data["network_changes"])
        self.assertEqual([item["scenario"] for item in data["health_checks"]], ["release", "parent_eof", "deadline"])

    def test_self_test_failure_stops_apply_before_vpn_prompt(self):
        with mock.patch.object(probe.sys, "argv", ["probe", "--apply", "--interactive"]), \
                mock.patch.object(probe, "self_test", return_value=2), \
                mock.patch.object(probe.signal, "signal"), \
                mock.patch("builtins.input") as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(), 2)
        prompt.assert_not_called()

    def test_launch_failure_is_not_misreported_as_unconfirmed_rollback(self):
        class FakeGuardian:
            def __init__(self, spec, events):
                pass
            def ready(self):
                raise probe.HelperNotStarted("not started")
            def release(self):
                return {"event": "not_started", "network_changes": False}
        fake_result = {"name": "test", "argv": ["mock"], "exit_code": 0,
                       "timeout": False, "seconds": 0, "output": "fixture"}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(probe, "OUTPUT", Path(directory)), \
                mock.patch.object(probe, "load_prepared", return_value={"protected_addresses": []}), \
                mock.patch.object(probe, "preflight", return_value=SPEC), \
                mock.patch.object(probe, "authenticate_sudo", return_value={"exit_code": 0}), \
                mock.patch.object(probe.diag, "batch", return_value=[]), \
                mock.patch.object(probe.diag, "command", return_value=fake_result), \
                mock.patch.object(probe.diag, "app_connections", return_value={"results": []}), \
                mock.patch.object(probe, "Guardian", FakeGuardian), \
                mock.patch.object(probe.signal, "signal"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.probe(True), 2)
            data = json.loads(next(Path(directory).glob("route-probe-*/report.json")).read_text())
        self.assertEqual(data["status"], "helper_not_started_no_changes")
        self.assertFalse(data["network_changes"])
        self.assertNotIn("rollback_confirmed", data)

    def test_stale_or_failed_preparation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "prepared.json"
            file.write_text(json.dumps({"schema": 1, "ready": False}))
            with mock.patch.object(probe, "PREPARED", file), self.assertRaises(helper.ProbeError):
                probe.load_prepared()
            data = {"schema": 1, "ready": True, "host": probe.HOST, "created_at": "2020-01-01T00:00:00+07:00"}
            file.write_text(json.dumps(data))
            with mock.patch.object(probe, "PREPARED", file), self.assertRaises(helper.ProbeError):
                probe.load_prepared()


if __name__ == "__main__":
    unittest.main()
