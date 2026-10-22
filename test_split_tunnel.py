import copy
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import route_probe_helper as base
import split_tunnel as app
import split_tunnel_helper as helper


SPEC = {"kind": helper.KIND, "seconds": 1800, "source": "192.168.88.102", "gateway": "192.168.88.1",
        "interface": "en0", "vpn_interface": "utun6", "server": "8.8.8.8",
        "work_addresses": ["10.77.0.53", "10.77.9.10", "203.0.113.40"]}


class FakeOperations:
    def __init__(self):
        self.entries = [
            {"prefix": "0.0.0.0/0", "gateway": "link#28", "flags": "UCSg", "interface": "utun6"},
            {"prefix": "0.0.0.0/0", "gateway": "192.168.88.1", "flags": "UGScIg", "interface": "en0"},
            {"prefix": "10.77.9.10/32", "gateway": "link#28", "flags": "UHWIig", "interface": "utun6"},
            {"prefix": "17.1.2.3/32", "gateway": "link#28", "flags": "UHWIig", "interface": "utun6"}]
        self.mutations = []
        self.context = {"interface": "utun6", "server": SPEC["server"]}
        self.physical_changed = False
        self.fail_at = None
        self.delete_fail = None
        self.force_vpn = False
        self.interface_gateway = "link#28"
        self.dns_raw = "nameserver[0] : 10.77.0.53\nnameserver[1] : 192.168.88.1\n"

    def index(self, interface):
        return 28

    def interface_gateways(self, interface):
        return ["utun6", "link#28", "10.254.1.110", "10.254.1.111"]

    def forti(self):
        if self.context is None:
            raise base.ProbeError("VPN disconnected")
        return self.context

    def physical(self, *args):
        if self.physical_changed:
            raise base.ProbeError("Physical network changed")
        return {key: SPEC[key] for key in ("gateway", "interface", "source")}

    def dns(self):
        return self.dns_raw

    def table(self):
        return copy.deepcopy(self.entries)

    def route(self, target):
        import ipaddress
        if target == SPEC["gateway"]:
            return {"destination": target, "gateway": "link#8", "interface": "en0"}
        rows = [row for row in self.entries if "I" not in row["flags"]
                and ipaddress.IPv4Address(target) in ipaddress.IPv4Network(row["prefix"])]
        row = max(rows, key=lambda row: ipaddress.IPv4Network(row["prefix"]).prefixlen)
        if self.force_vpn and target == "1.1.1.1":
            return {"interface": "utun6"}
        return {"destination": row["prefix"].removesuffix("/32"), "gateway": row["gateway"], "interface": row["interface"]}

    def run(self, argv):
        self.mutations.append(argv)
        verb = argv[2]
        scoped = "-ifscope" in argv
        target = argv[-1] if scoped else argv[4]
        prefix = helper.network(target)
        if verb == "add":
            via_interface = "-interface" in argv
            self.entries.append({"prefix": prefix, "gateway": self.interface_gateway if via_interface else argv[-1],
                                 "flags": "UHS" if via_interface else "UGHS" if prefix.endswith("/32") else "UGS",
                                 "interface": argv[-1] if via_interface else "en0"})
            if prefix == self.fail_at:
                raise base.ProbeError("timeout after accepted add")
        elif verb == "delete":
            if prefix == self.delete_fail:
                raise base.ProbeError("delete failed")
            if scoped:
                self.entries = [r for r in self.entries if not (r["prefix"] == prefix and "I" in r["flags"])]
            else:
                self.entries = [r for r in self.entries if not (r["prefix"] == prefix and "I" not in r["flags"])]
        return "fixture"


class SplitLeaseTests(unittest.TestCase):
    def setUp(self):
        self.ops = FakeOperations()
        self.journal = []
        self.lease = helper.SplitLease(copy.deepcopy(SPEC), self.ops, self.journal.append)

    def test_additive_routes_and_exact_reverse_rollback(self):
        initial = [row for row in self.ops.entries if "W" not in row["flags"]]
        plan = self.lease.begin()
        self.assertEqual(plan["dns_policy"], "unchanged_corporate_via_vpn")
        self.assertEqual(self.ops.route("1.1.1.1")["interface"], "en0")
        for address in SPEC["work_addresses"]:
            self.assertEqual(self.ops.route(address)["interface"], "utun6")
        self.assertEqual(self.ops.route(SPEC["server"])["interface"], "en0")
        self.assertEqual(self.journal[0]["entries"], [])
        # Journal snapshots must not change after recording.
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertEqual(self.ops.entries, initial)
        self.assertEqual(self.journal[-1], {"status": "inactive"})
        added = [a for a in self.ops.mutations if a[2] == "add"]
        deleted = [a for a in self.ops.mutations if a[2] == "delete" and "-ifscope" not in a]
        self.assertEqual([a[4] for a in deleted], [a[4] for a in reversed(added)])

    def test_dry_run_has_no_mutation_or_journal(self):
        self.lease.plan()
        self.assertEqual(self.ops.mutations, [])
        self.assertEqual(self.journal, [])

    def test_existing_static_work_host_and_other_routes_preserved(self):
        row = {"prefix": "10.77.9.10/32", "gateway": "10.254.0.235", "flags": "UGHS", "interface": "utun6"}
        self.ops.entries.append(row)
        plan = self.lease.begin()
        self.assertNotIn("10.77.9.10/32", [e["prefix"] for e in plan["add"]])
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertIn(row, self.ops.entries)

    def test_both_scoped_and_unscoped_prefix_conflicts_block_all_changes(self):
        for flags in ("UGS", "UGSI"):
            self.ops.entries.append({"prefix": "0.0.0.0/1", "gateway": "1.2.3.4", "flags": flags, "interface": "en1"})
            with self.assertRaises(base.ProbeError):
                self.lease.begin()
            self.assertEqual(self.ops.mutations, [])

    def test_changed_network_or_vpn_blocks_mutations(self):
        self.ops.physical_changed = True
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertEqual(self.ops.mutations, [])
        self.ops.physical_changed = False
        self.ops.context = {"interface": "utun7", "server": SPEC["server"]}
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertEqual(self.ops.mutations, [])

    def test_partial_add_timeout_is_recoverable(self):
        self.ops.fail_at = "0.0.0.0/1"
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertFalse(any(r["prefix"] in helper.PREFIXES for r in self.ops.entries))

    def test_point_to_point_local_ipv4_gateway_is_captured_and_rolled_back(self):
        self.ops.interface_gateway = "10.254.1.110"
        self.lease.begin()
        pins = [entry for entry in self.lease.entries if entry["via"] == "interface"]
        self.assertTrue(pins)
        self.assertTrue(all(entry["gateway"] == "10.254.1.110" for entry in pins))
        self.assertTrue(all("pending_gateways" not in entry for entry in pins))
        observations = self.lease.observations
        self.assertTrue(any(row["gateway"] == "10.254.1.110" for row in observations[0]["rows"]))
        self.assertTrue(self.lease.rollback()["ok"])

    def test_real_1701_named_gateway_fixture_is_confirmed_and_rolled_back(self):
        # Actual after_add receipt from split-session-20261022-170110-458715.
        raw = "Internet:\nDestination Gateway Flags Netif Expire\n10.77.0.53 utun6 UHS utun6\n"
        row = helper.table(raw)[0]
        self.assertEqual(row, {"prefix": "10.77.0.53/32", "gateway": "utun6", "flags": "UHS", "interface": "utun6"})
        self.ops.interface_gateway = row["gateway"]
        self.lease.begin()
        self.assertIn(row, self.ops.table())
        entry = next(entry for entry in self.lease.entries if entry["prefix"] == row["prefix"])
        self.assertEqual(entry["gateway"], "utun6")
        self.assertNotIn("pending_gateways", entry)
        self.assertTrue(helper.same(row, entry))
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertNotIn(row, self.ops.table())

    def test_named_gateway_is_not_an_alias_for_another_interface(self):
        self.ops.interface_gateway = "utun7"
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertFalse(self.lease.rollback()["ok"])
        self.assertTrue(any(row["gateway"] == "utun7" for row in self.ops.table()))

    def test_all_three_display_forms_work_with_initial_confirmation_and_rollback(self):
        for gateway in ("utun6", "link#28", "10.254.1.110"):
            with self.subTest(gateway=gateway):
                ops = FakeOperations()
                ops.interface_gateway = gateway
                lease = helper.SplitLease(copy.deepcopy(SPEC), ops)
                lease.begin()
                lease.check()
                self.assertTrue(all(entry["gateway"] == gateway for entry in lease.entries if entry["via"] == "interface"))
                self.assertTrue(lease.rollback()["ok"])

    def test_named_gateway_timeout_after_add_remains_recoverable(self):
        self.ops.interface_gateway = "utun6"
        self.ops.fail_at = "10.77.0.53/32"
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertTrue(self.lease.rollback()["ok"])

    def test_timeout_after_local_ipv4_add_uses_write_ahead_aliases_to_rollback(self):
        self.ops.interface_gateway = "10.254.1.110"
        self.ops.fail_at = "10.77.0.53/32"
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        self.assertEqual(self.lease.observations[0]["phase"], "after_add")
        self.assertTrue(self.lease.rollback()["ok"])

    def test_unrelated_gateway_never_adopted_just_because_interface_matches(self):
        self.ops.interface_gateway = "10.254.7.250"
        with self.assertRaises(base.ProbeError):
            self.lease.begin()
        rollback = self.lease.rollback()
        self.assertFalse(rollback["ok"])
        self.assertTrue(any(row["gateway"] == "10.254.7.250" for row in self.ops.entries))
        self.assertEqual(rollback["observations"][0]["rows"][0]["gateway"], "10.254.7.250")

    def test_confirmed_gateway_replaced_by_other_local_address_is_not_deleted(self):
        self.ops.interface_gateway = "10.254.1.110"
        self.lease.begin()
        for row in self.ops.entries:
            if row["prefix"] == "10.77.0.53/32":
                row["gateway"] = "10.254.1.111"
        self.assertFalse(self.lease.rollback()["ok"])
        self.assertTrue(any(row["gateway"] == "10.254.1.111" for row in self.ops.entries))

    def test_legacy_journal_with_absent_route_is_cleared_without_any_deletes(self):
        self.lease.entries = [{"prefix": "10.77.0.53/32", "gateway": "link#28", "interface": "utun6", "via": "interface"}]
        self.lease.armed = True
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertEqual(self.ops.mutations, [])
        self.assertEqual(self.journal[-1], {"status": "inactive"})

    def test_legacy_journal_does_not_adopt_an_unknown_present_route(self):
        self.lease.entries = [{"prefix": "10.77.0.53/32", "gateway": "link#28", "interface": "utun6", "via": "interface"}]
        self.lease.armed = True
        self.ops.entries.append({"prefix": "10.77.0.53/32", "gateway": "10.254.1.110", "interface": "utun6", "flags": "UHS"})
        self.assertFalse(self.lease.rollback()["ok"])
        self.assertEqual(self.ops.mutations, [])

    def test_multicast_clones_are_not_removed(self):
        row = {"prefix": "239.255.255.250/32", "gateway": "link#28", "flags": "UHmW3I", "interface": "utun6"}
        self.ops.entries.append(row)
        self.lease.begin()
        self.assertIn(row, self.ops.entries)
        self.assertTrue(self.lease.rollback()["ok"])
        self.assertIn(row, self.ops.entries)

    def test_gateway_choices_come_from_interface_local_addresses_not_peer(self):
        run = mock.Mock(return_value="utun6: flags=8051\n\tinet 10.254.1.110 --> 10.254.0.235 netmask 0xffffffff\n")
        ops = helper.Operations(runner=run)
        with mock.patch.object(ops, "index", return_value=28):
            self.assertEqual(ops.interface_gateways("utun6"), ["10.254.1.110", "link#28", "utun6"])
        run.assert_called_once_with(["/sbin/ifconfig", "utun6"])

    def test_foreign_replacement_keeps_journal_and_does_not_delete_work_pins(self):
        self.lease.begin()
        for row in self.ops.entries:
            if row["prefix"] == "128.0.0.0/1":
                row["gateway"] = "192.168.88.254"
        self.assertFalse(self.lease.rollback()["ok"])
        self.assertTrue(any(r["gateway"] == "192.168.88.254" for r in self.ops.entries))
        self.assertEqual(self.journal[-1]["status"], "armed")
        self.assertEqual(self.ops.route("10.77.9.10")["interface"], "utun6")

    def test_failed_broad_delete_keeps_work_pins(self):
        self.lease.begin()
        self.ops.delete_fail = "128.0.0.0/1"
        self.assertFalse(self.lease.rollback()["ok"])
        self.assertEqual(self.ops.route("10.77.9.10")["interface"], "utun6")

    def test_guard_check_detects_disconnect_reconnect_dns_and_forced_vpn(self):
        self.lease.begin()
        for change in ("disconnect", "reconnect", "dns", "forced", "physical"):
            with self.subTest(change=change):
                original = copy.deepcopy(self.ops.__dict__)
                if change == "disconnect":
                    self.ops.context = None
                elif change == "reconnect":
                    self.ops.context["interface"] = "utun7"
                elif change == "dns":
                    self.ops.dns_raw += "nameserver[2] : 8.8.8.8\n"
                elif change == "forced":
                    self.ops.force_vpn = True
                else:
                    self.ops.physical_changed = True
                with self.assertRaises(base.ProbeError):
                    self.lease.check()
                self.ops.__dict__ = original

    def test_recovery_after_vpn_is_gone_does_not_require_vpn_or_physical_network(self):
        self.lease.begin()
        entries = copy.deepcopy(self.lease.entries)
        self.ops.context = None
        self.ops.physical_changed = True
        recovered = helper.SplitLease(copy.deepcopy(SPEC), self.ops, self.journal.append)
        recovered.entries = entries
        recovered.armed = True
        self.assertTrue(recovered.rollback()["ok"])

    def test_validation_blocks_dangerous_addresses_and_unbounded_duration(self):
        for value in ("127.0.0.1", "224.0.0.1", "0.0.0.0", "::1", SPEC["server"], SPEC["gateway"]):
            with self.assertRaises((base.ProbeError, ValueError)):
                helper.SplitLease(dict(SPEC, work_addresses=[value]))
        for seconds in (-1, 59, 28801, True):
            with self.assertRaises(base.ProbeError):
                helper.SplitLease(dict(SPEC, seconds=seconds))

    def test_parser_and_route_syntax(self):
        self.assertEqual(helper.network("0/1"), "0.0.0.0/1")
        self.assertEqual(helper.network("128.0/1"), "128.0.0.0/1")
        self.assertEqual(helper.network("192.168.88"), "192.168.88.0/24")
        self.assertEqual(helper.network("10.77.9.10"), "10.77.9.10/32")
        entry = {"prefix": "10.77.9.10/32", "via": "interface", "interface": "utun6", "gateway": "link#28"}
        self.assertEqual(helper.route_command("add", entry), ["/sbin/route", "-n", "add", "-host", "10.77.9.10", "-interface", "utun6"])

    def test_eof_release_deadline_and_sleep_guard(self):
        poll = lambda *args: ([9], [], [])
        self.assertEqual(helper.guard(9, 20, self.lease, clock=lambda: 0, poll=poll, reader=lambda *a: b""), "parent_eof")
        self.assertEqual(helper.guard(9, 20, self.lease, clock=lambda: 0, poll=poll, reader=lambda *a: b"stop"), "release")
        self.assertEqual(helper.guard(9, 20, self.lease, clock=lambda: 21), "deadline")
        wall = iter([0, 100])
        with self.assertRaises(base.ProbeError):
            helper.guard(9, 20, self.lease, clock=lambda: 0, poll=lambda *a: ([], [], []), wall=lambda: next(wall))


class LoginDiagnosisTests(unittest.TestCase):
    def test_only_whitelisted_events_and_no_auth_values_are_saved(self):
        raw = "\n".join([
            "20261022 16:26:42.373 TZ=+0700 [FortiTray:INFO] X:1 Request VPN connect",
            "20261022 16:26:42.442 TZ=+0700 [FortiTray:DEBG] X:1 Resolved IP address 8.8.4.4 for domain name: private.test",
            "20261022 16:26:44.471 TZ=+0700 [FortiTray:DEBG] HttpsNWConnection.swift:130 Connected to 8.8.4.4",
            "20261022 16:27:17.543 TZ=+0700 [FortiTray:DEBG] X:1 Server requires RSA PIN",
            "20261022 16:27:31.309 TZ=+0700 [FortiTray:DEBG] X:1 otp=123456 password=never-save-me",
            "20261022 16:32:25.570 TZ=+0700 [FortiTray:INFO] X:1 Error from server: Permission denied.",
            "20261022 16:32:25.573 TZ=+0700 [FortiTray:INFO] X:1 Login failed. Result: 4",
        ])
        events = app.login_events(raw, "20261022")
        self.assertEqual([event["event"] for event in events], ["connect_requested", "gateway_resolved",
                         "gateway_transport_connected", "mfa_requested", "server_permission_denied", "login_failed"])
        encoded = json.dumps(events)
        self.assertNotIn("123456", encoded)
        self.assertNotIn("never-save-me", encoded)
        self.assertNotIn("private.test", encoded)

    def test_prior_days_and_unrecognized_messages_are_excluded(self):
        raw = "20261021 16:32:25.570 TZ=+0700 [FortiTray:INFO] X:1 Error from server: Permission denied.\n"
        self.assertEqual(app.login_events(raw, "20261022"), [])

    def test_read_only_check_does_not_save_raw_logs_or_run_sudo(self):
        def result(name, text):
            return {"name": name, "argv": ["fixture"], "exit_code": 0, "timeout": False, "seconds": 0, "output": text}
        state = [result("VPN services", "Disconnected"), result("IPv4 routes", "default 192.168.88.1 UGSc en0"), result("DNS", "nameserver[0] : 192.168.88.1")]
        day = app.dt.datetime.now(app.diag.TZ).strftime("%Y%m%d")
        raw = day + " 16:32:25.570 TZ=+0700 [FortiTray:INFO] X:1 Error from server: Permission denied.\nprivate-secret-123"
        def command(name, argv, timeout):
            return result(name, raw if argv[0] == "/usr/bin/tail" else "123 1 /Applications/VMware Fusion.app/vmware-vmx\n999 1 unrelated-secret-process")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(app, "OUTPUT", Path(directory)), \
             mock.patch.object(app.diag, "batch", return_value=state), \
             mock.patch.object(app.diag, "command", side_effect=command) as execute, \
             mock.patch.object(app.probe, "authenticate_sudo") as auth, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.connection_check(), 0)
            saved = next(Path(directory).glob("*/report.json")).read_text()
            self.assertNotIn("private-secret-123", saved)
            self.assertNotIn("unrelated-secret-process", saved)
            self.assertTrue(json.loads(saved)["connection_diagnosis"]["vm_running"])
            self.assertTrue(json.loads(saved)["connection_diagnosis"]["server_permission_denied_observed_today"])
        auth.assert_not_called()
        self.assertEqual([call.args[1][0] for call in execute.call_args_list], ["/usr/bin/tail", "/bin/ps"])

    def test_error_response_collects_diagnosis_instead_of_applying_routes(self):
        with mock.patch.object(app.sys, "argv", ["app", "--apply", "--interactive"]), \
             mock.patch.object(app.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(app.signal, "signal"), mock.patch.object(app, "prepare", return_value=0), \
             mock.patch.object(app.probe, "self_test", return_value=0), \
             mock.patch.object(app, "recover", return_value=0), mock.patch("builtins.input", return_value="ОШИБКА"), \
             mock.patch.object(app, "connection_check", return_value=0) as check, \
             mock.patch.object(app, "session") as session, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.main(), 0)
        check.assert_called_once()
        session.assert_not_called()

    def test_enter_without_connected_vpn_collects_diagnosis_and_never_applies(self):
        ops = mock.Mock()
        ops.forti.side_effect = base.ProbeError("VPN disconnected")
        with mock.patch.object(app.sys, "argv", ["app", "--apply", "--interactive"]), \
             mock.patch.object(app.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(app.signal, "signal"), mock.patch.object(app, "prepare", return_value=0), \
             mock.patch.object(app.probe, "self_test", return_value=0), \
             mock.patch.object(app, "recover", return_value=0), mock.patch("builtins.input", return_value=""), \
             mock.patch.object(app.helper, "Operations", return_value=ops), \
             mock.patch.object(app, "connection_check", return_value=0) as check, \
             mock.patch.object(app, "session") as session, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.main(), 2)
        check.assert_called_once()
        session.assert_not_called()


class ControllerTests(unittest.TestCase):
    def test_failed_recovery_stops_interactive_flow_before_vpn_prompt(self):
        with mock.patch.object(app.sys, "argv", ["split_tunnel.py", "--apply", "--interactive"]), \
             mock.patch.object(app.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(app.signal, "signal"), \
             mock.patch.object(app, "prepare", return_value=0), \
             mock.patch.object(app.probe, "self_test", return_value=0), \
             mock.patch.object(app, "recover", return_value=3) as recover, \
             mock.patch("builtins.input") as prompt, \
             mock.patch.object(app, "session") as session, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.main(), 3)
        recover.assert_called_once_with(no_prompt=True)
        prompt.assert_not_called()
        session.assert_not_called()

    def test_background_controller_responds_during_parent_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(app, "CONTROL_DIR", root / "control"), mock.patch.object(app, "CONTROL", root / "control" / "control.sock"):
                server = app.Controller(root)
                try:
                    server.state = "active"
                    self.assertEqual(app.request_control("status")["state"], "active")
                    self.assertEqual(app.request_control("status")["pid"], os.getpid())
                    self.assertEqual(app.request_control("stop")["state"], "active")
                    self.assertTrue(server.stop_requested.wait(2))
                finally:
                    server.close()

    def test_user_socket_status_stop_and_single_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(app, "CONTROL_DIR", root / "control"), mock.patch.object(app, "CONTROL", root / "control" / "control.sock"):
                server = app.Controller(root, serve=False)
                try:
                    with self.assertRaises(base.ProbeError):
                        app.Controller(root)
                    for command in ("status", "stop"):
                        output = []
                        thread = threading.Thread(target=lambda: output.append(app.request_control(command)))
                        thread.start()
                        stopped = server.receive()
                        thread.join(3)
                        self.assertEqual(stopped, command == "stop")
                        self.assertEqual(output[0]["state"], "starting")
                        self.assertEqual(output[0]["report"], str(root / "report.json"))
                finally:
                    server.close()
                self.assertIsNone(app.request_control("status"))

    def test_control_directory_rejects_symlink_and_open_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / "bad"
            bad.mkdir(mode=0o755)
            with mock.patch.object(app, "CONTROL_DIR", bad):
                with self.assertRaises(base.ProbeError):
                    app.control_directory()
            link = root / "link"
            link.symlink_to(bad)
            with mock.patch.object(app, "CONTROL_DIR", link):
                with self.assertRaises(base.ProbeError):
                    app.control_directory()

    def test_spec_preserves_only_work_app_observations_and_skips_ipv6(self):
        ops = FakeOperations()
        prepared = {**{k: SPEC[k] for k in ("interface", "gateway", "source")},
                    "config": {"work": SPEC["work_addresses"], "seconds": 1800},
                    "public_pins": {"example.com": {"4": "1.1.1.1"}}}
        spec, skipped = app.make_spec(prepared, ops, {"observed_peers": ["10.77.9.20", "::1", SPEC["gateway"]]})
        self.assertIn("10.77.9.20", spec["work_addresses"])
        self.assertEqual(skipped, ["::1"])
        self.assertNotIn(SPEC["gateway"], spec["work_addresses"])

    def test_report_is_private_and_does_not_claim_ipv6(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            app.report({"started_at": "fixture", "status": "dry_run_no_network_changes"}, folder)
            self.assertEqual((folder / "report.json").stat().st_mode & 0o777, 0o600)
            self.assertIn("НЕ подтверждён", (folder / "report.txt").read_text())


class HelperProtocolTests(unittest.TestCase):
    def test_new_helper_health_never_touches_journal_or_network(self):
        with mock.patch.object(helper.sys, "argv", ["helper", "health"]), \
             mock.patch.object(helper.os, "geteuid", return_value=0), \
             mock.patch.object(helper.base, "emit"), \
             mock.patch.object(helper.base, "health_check", return_value=0) as health, \
             mock.patch.object(helper.base, "acquire_journal") as journal, \
             mock.patch.object(helper, "Operations") as operations:
            self.assertEqual(helper.main(), 0)
        health.assert_called_once()
        journal.assert_not_called()
        operations.assert_not_called()

    def test_main_rolls_back_on_pipe_eof_deadline_and_guard_failure(self):
        for reason in ("parent_eof", "deadline", "error"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                ops = FakeOperations()
                events = []
                fd = os.open(str(Path(directory) / "journal"), os.O_CREAT | os.O_RDWR, 0o600)
                stream = SimpleNamespace(buffer=io.BytesIO((json.dumps(SPEC) + "\n").encode()), fileno=lambda: 0)
                def guard(*args):
                    if reason == "error":
                        raise base.ProbeError("watchdog fixture")
                    return reason
                with mock.patch.object(helper.sys, "argv", ["split_tunnel_helper.py", "lease"]), \
                     mock.patch.object(helper.sys, "stdin", stream), \
                     mock.patch.object(helper.os, "geteuid", return_value=0), \
                     mock.patch.object(helper.base, "acquire_journal", return_value=(fd, {"status": "inactive"})), \
                     mock.patch.object(helper, "Operations", return_value=ops), \
                     mock.patch.object(helper.select, "select", return_value=([stream], [], [])), \
                     mock.patch.object(helper.signal, "signal"), \
                     mock.patch.object(helper.base, "emit", side_effect=events.append), \
                     mock.patch.object(helper, "guard", side_effect=guard):
                    code = helper.main()
                self.assertEqual(code, 1 if reason == "error" else 0)
                self.assertEqual(events[0]["event"], "hello")
                self.assertTrue(any(event["event"] == "ready" for event in events))
                self.assertEqual(events[-1]["event"], "rolled_back")
                self.assertTrue(events[-1]["rollback"]["ok"])
                self.assertFalse(any(row["prefix"] in helper.PREFIXES for row in ops.entries))

    def test_recovery_refuses_another_user_or_probe_journal_without_any_route_mutations(self):
        for kind, owner in (("single-host", os.getuid()), (helper.KIND, os.getuid() + 1)):
            with tempfile.TemporaryDirectory() as directory:
                ops = FakeOperations()
                fd = os.open(str(Path(directory) / "journal"), os.O_CREAT | os.O_RDWR, 0o600)
                previous = {"status": "armed", "kind": kind, "owner": owner}
                with mock.patch.object(helper.sys, "argv", ["helper", "recover"]), \
                     mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
                     mock.patch.object(helper.os, "geteuid", return_value=0), \
                     mock.patch.object(helper.base, "acquire_journal", return_value=(fd, previous)), \
                     mock.patch.object(helper, "Operations", return_value=ops), \
                     mock.patch.object(helper.base, "emit"):
                    self.assertEqual(helper.main(), 1)
                self.assertEqual(ops.mutations, [])

    def test_large_recovery_journal_is_not_truncated_to_single_host_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal"
            value = {"status": "armed", "fixture": "x" * 20000}
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            real_stat = os.fstat
            def root_stat(fd):
                info = real_stat(fd)
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
            with mock.patch.object(base, "LOCK_FILE", str(path)), mock.patch.object(base.os, "fstat", side_effect=root_stat):
                fd, loaded = base.acquire_journal()
                os.close(fd)
                self.assertEqual(loaded, value)

    def test_parent_sudo_failure_never_claims_network_was_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            data = {"started_at": "fixture", "status": "started", "notes": [], "stages": [], "guardian_events": []}
            prepared = {**{k: SPEC[k] for k in ("interface", "gateway", "source")},
                        "config": {"work": SPEC["work_addresses"], "seconds": 1800},
                        "public_pins": {"example.com": {"4": "1.1.1.1"}}}
            controller = mock.Mock()
            controller.stop_requested.is_set.return_value = False
            with mock.patch.object(app, "new_report", return_value=(folder, data)), \
                 mock.patch.object(app, "load_prepared", return_value=prepared), \
                 mock.patch.object(app, "Controller", return_value=controller), \
                 mock.patch.object(app.helper, "Operations", return_value=FakeOperations()), \
                 mock.patch.object(app, "work_connections", return_value={"label": "fixture", "at": "fixture", "observed_peers": [], "results": []}), \
                 mock.patch.object(app.sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(app, "confirm_plan", return_value=True), \
                 mock.patch.object(app.probe, "authenticate_sudo", return_value={"exit_code": 1}), \
                 mock.patch.object(app, "start_guardian") as start, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(app.session(), 2)
            start.assert_not_called()
            self.assertEqual(data["status"], "blocked_no_network_changes")
            controller.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
