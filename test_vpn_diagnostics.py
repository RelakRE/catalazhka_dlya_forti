import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import vpn_diagnostics as diag


def result(name, output="", code=0, timed_out=False):
    return {"name": name, "argv": ["mock-read-only-command"], "exit_code": code,
            "timeout": timed_out, "seconds": 0.0, "output": output}


def fake_command(name, argv, timeout=10):
    if name == "VPN services":
        return result(name, "* (Disconnected) 12345678-1234-1234-1234-123456789012 "
                      "VPN (com.fortinet.forticlient.macos.vpn) VPN")
    if name == "FortiClient connection status":
        return result(name, "Disconnected")
    if name.startswith("HTTPS"):
        if "IPv6" in name:
            return result(name, "http_code=000\nremote_ip=\ntls_verify=0", 7)
        return result(name, "http_code=200\nremote_ip=192.0.2.20\ntls_verify=0")
    return result(name, "fixture network state")


class DiagnosticsTests(unittest.TestCase):
    def test_targets_validate_before_any_network_call(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "targets.txt"
            file.write_text("# comment\nrdp desktop.corp.example 3389\n"
                            "conf 192.0.2.5 4307\nv6 2001:db8::3 443\n")
            self.assertEqual(len(diag.load_targets(file)), 3)
            for invalid in ("rdp https://user:password@host 3389", "rdp host 99999",
                            "rdp 10.0.0.0/8 3389", "rdp --option 3389",
                            "rdp bad..host 3389", "rdp host 443 extra"):
                file.write_text(invalid)
                with self.assertRaises(ValueError, msg=invalid):
                    diag.load_targets(file)

    def test_collects_related_executables_and_descendants_not_unrelated_apps(self):
        raw = "10 1 /Applications/Windows App.app/Contents/MacOS/Windows App\n" \
              "11 10 /usr/libexec/helper\n12 11 /usr/libexec/second-helper\n" \
              "20 1 /Applications/Safari.app/Contents/MacOS/Safari\n"
        self.assertEqual([row[0] for row in diag.related_processes(raw)], [10, 11, 12])

    def test_lsof_peers_ipv4_ipv6_and_listening_sockets(self):
        raw = "p10\ncWindows App\nn192.0.2.2:100->10.2.3.4:3389\n" \
              "n[2001:db8::2]:200->[2001:db8::3]:443\nn*:3389\n" \
              "n127.0.0.1:100->127.0.0.1:200\nn192.0.2.2:100->hostname:443\n"
        self.assertEqual(diag.peer_addresses(raw), ["10.2.3.4", "2001:db8::3"])

    def test_dns_address_parsing(self):
        raw = "name: host\nip_address: 10.1.2.3\nipv6_address: 2001:db8::4\n"
        self.assertEqual(diag.resolved_addresses(raw), ["10.1.2.3", "2001:db8::4"])
        self.assertEqual(diag.dns_server_addresses("nameserver[0] : 10.1.1.2\n"
                                                  "nameserver[1] : fe80::1%en0\n"
                                                  "nameserver[0] : 10.1.1.2"),
                         ["10.1.1.2", "fe80::1%en0"])

    def test_only_successful_tls_probe_can_seed_pinned_ip(self):
        good = result("HTTPS example.com IPv4 system DNS",
                      "http_code=301\nremote_ip=192.0.2.20\ntls_verify=0")
        self.assertEqual(diag.verified_pins([good]), {"example.com": {"4": "192.0.2.20"}})
        for bad in (dict(good, exit_code=60), dict(good, timeout=True),
                    dict(good, output=good["output"].replace("tls_verify=0", "tls_verify=20")),
                    dict(good, output=good["output"].replace("http_code=301", "http_code=000"))):
            self.assertEqual(diag.verified_pins([bad]), {})

    def test_ipv4_mapped_response_is_not_native_ipv6(self):
        mapped = result("HTTPS example.com IPv6 system DNS",
                        "http_code=200\nremote_ip=::ffff:192.0.2.20\ntls_verify=0")
        self.assertEqual(diag.verified_pins([mapped]), {})

    def test_pinned_ipv6_preserves_tls_and_disables_proxy_and_curlrc(self):
        _, argv, _ = diag.curl_job("example.com", "6", "2001:db8::2")
        self.assertEqual(argv[1], "-q")
        self.assertIn("example.com:443:[2001:db8::2]", argv)
        self.assertIn("--noproxy", argv)
        self.assertNotIn("--insecure", argv)
        self.assertNotIn("--verbose", argv)
        with self.assertRaises(ValueError):
            diag.curl_job("example.com", "4", "2001:db8::2")

    def test_connected_checks_reuse_baseline_ip_not_new_dns_results(self):
        jobs = []
        with mock.patch.object(diag, "batch", side_effect=lambda items: jobs.extend(items) or []):
            diag.public_checks({"public_pins": {"example.com": {"4": "192.0.2.20"}}})
        all_args = [argv for _, argv, _ in jobs]
        pinned = [argv for argv in all_args if "--resolve" in argv]
        self.assertEqual(len(pinned), 1)
        self.assertIn("example.com:443:192.0.2.20", pinned[0])

    def test_timeout_and_missing_commands_are_reported_not_raised(self):
        with mock.patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(
                ["/mock"], 1, output=b"partial output")):
            item = diag.command("test", ["/mock"], 1)
        self.assertTrue(item["timeout"])
        self.assertEqual(item["output"], "partial output")
        with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError("missing")):
            self.assertIsNone(diag.command("test", ["/mock"])["exit_code"])

    def test_redacts_proxy_urls_credentials_and_terminal_escapes(self):
        cleaned = diag.clean_output("ProxyAutoConfigURLString : https://user:secret@host/a?key=value\n"
                                    "password: hidden\n\tether 00:11:22:33:44:55\n"
                                    "\x1b[31mDNS: corp.example\x1b[0m")
        for omitted in ("https://", "hidden", "00:11", "\x1b"):
            self.assertNotIn(omitted, cleaned)
        self.assertIn("corp.example", cleaned)

    def test_complete_baseline_and_connected_report_with_failed_network_checks(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diag, "command", side_effect=fake_command), \
                contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            baseline_dir, code = diag.collect("baseline", root, [])
            self.assertEqual(code, 0)
            connected_dir, code = diag.collect("connected", root, [])
            self.assertEqual(code, 0)
            data = json.loads((connected_dir / "report.json").read_text())
            report = (connected_dir / "report.txt").read_text()
            self.assertEqual(data["status"], "complete")
            self.assertEqual(data["baseline_path"], str(baseline_dir / "report.txt"))
            self.assertIn("BEFORE VPN", report)
            self.assertIn("ИЗМЕНЕНИЯ ДО / ПОСЛЕ", report)
            self.assertIn("baseline IP (no DNS)", report)
            self.assertEqual((connected_dir / "report.txt").stat().st_mode & 0o777, 0o600)

    def test_rejects_baseline_when_forticlient_connected(self):
        def connected_status(name, argv, timeout=10):
            return result(name, "Connected") if name == "FortiClient connection status" \
                else fake_command(name, argv, timeout)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diag, "command", side_effect=connected_status), \
                contextlib.redirect_stdout(io.StringIO()):
            folder, code = diag.collect("baseline", Path(directory), [])
            self.assertEqual(code, 2)
            self.assertTrue((folder / "report.txt").exists())
            self.assertEqual(diag.find_baseline(Path(directory)), (None, None))

    def test_partial_report_survives_collector_error(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(diag, "command", side_effect=fake_command), \
                mock.patch.object(diag, "public_checks", side_effect=RuntimeError("test failure")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            folder, code = diag.collect("connected", Path(directory), [])
            self.assertEqual(code, 1)
            data = json.loads((folder / "report.json").read_text())
            self.assertEqual(data["status"], "error")
            self.assertEqual(len(data["stages"]), 2)
            self.assertIn("test failure", (folder / "report.txt").read_text())


if __name__ == "__main__":
    unittest.main()
