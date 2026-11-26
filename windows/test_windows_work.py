from pathlib import Path
import unittest
from release_notes import release_notes

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'FortiSplit.Work'

class WorkSafety(unittest.TestCase):
    def test_release_card_contains_only_the_requested_version(self):
        history = "# Windows 1.2.10 Preview\r\n\r\n- Новый выпуск\r\n\r\n# Windows 1.2.1 Preview\r\n\r\n## Changes\r\nDetails\r\n"
        self.assertEqual(release_notes(history, "1.2.10"), "- Новый выпуск")
        self.assertEqual(release_notes(history, "1.2.1"), "## Changes\r\nDetails")
        for invalid in ("", "# Windows 1.2.10 Preview\n", history + history):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                release_notes(invalid, "1.2.10")

    def test_network_writes_only_tunnel_host_routes(self):
        code = (SRC / 'Network.ps1').read_text(encoding='utf-8-sig')
        self.assertIn("$prefix=$IP+'/32'", code)
        self.assertIn("$adapter.Name -ne 'FortiSplitWork'", code)
        self.assertIn("$s.Tag -ne $tag", code)
        for forbidden in ('Set-DnsClientServerAddress', 'DisableDefaultRoutes', 'Remove-NetAdapter', 'Set-NetFirewall', '0.0.0.0/0'):
            self.assertNotIn(forbidden, code)

    def test_credentials_only_use_private_channels(self):
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertIn('AuthPipe.Login', worker)
        self.assertIn('"--cookie-on-stdin"', worker)
        self.assertIn('vpn.StandardInput.WriteLine(login.Cookie)', worker)
        for forbidden in ('info.ArgumentList.Add(login.Cookie)', 'info.ArgumentList.Add(password)', '--dump-http', '--servercert'):
            self.assertNotIn(forbidden, worker)
        ipc = (SRC / 'AuthPipe.cs').read_text(encoding='utf-8')
        self.assertIn('VerifyServer(client,parentPid)', ipc)
        self.assertIn('TokenImpersonationLevel.Identification', ipc)
        self.assertIn('65536', ipc)
        ui = (SRC / 'MainForm.Auth.cs').read_text(encoding='utf-8')
        self.assertIn('PipeOptions.CurrentUserOnly', ui)
        self.assertIn('VerifyClient(server,workerPid)', ui)
        self.assertIn('request.Kind=="authenticated"', ui)

    def test_manual_recovery_only_stops_recorded_process(self):
        code = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertNotIn('--watch', code)
        self.assertIn('child.StartTime.ToUniversalTime().Ticks!=saved.StartTicks', code)
        self.assertIn('child.MainModule?.FileName', code)
        self.assertNotIn('GetProcessesByName("Forti', code)
        self.assertNotIn('Kill(true)', code)

    def test_dns_is_outside_synchronous_hook(self):
        code = (SRC / 'Network.ps1').read_text(encoding='utf-8-sig')
        hook = code.split("if ($Mode -eq 'Hook') {", 1)[1].split('Get-NetAdapter -InterfaceIndex $script:state.Index', 1)[0]
        self.assertNotIn('Resolve-DnsName', hook)
        self.assertIn('Set-WorkDns', hook)
        self.assertLess(hook.index('foreach($name in $literals)'), hook.index("Stage='base_ready'"))

    def test_worker_uses_the_same_stop_condition_during_auth_and_tunnel(self):
        code = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertIn('parent is {HasExited:true}', code)
        self.assertIn('!vpn.HasExited&&!StopRequested()', code)
        self.assertIn('AuthPipe.Login(id,parentId,config,StopRequested,', code)
        self.assertIn('if((StopRequested()||cleanupRequired) && scriptsReady)', code)
        shutdown = code.split('if((StopRequested()||cleanupRequired) && scriptsReady)', 1)[1]
        self.assertLess(shutdown.index('TryState(folder,"disconnecting"'), shutdown.index('GenerateConsoleCtrlEvent(0,0)'))
        self.assertLess(shutdown.index('GenerateConsoleCtrlEvent(0,0)'), shutdown.index('Script(folder,"Cleanup")'))

    def test_worker_observes_hook_failures_after_first_connection(self):
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        loop = worker.split('while(SessionActive())', 1)[1]
        self.assertIn('if(NetworkHookFailed(folder))', loop)
        self.assertIn('throw NetworkFailure(', loop)
        self.assertIn('Stopwatch.GetElapsedTime(started)>=NetworkReadyLimit', loop)
        hook = (SRC / 'network-hook.js').read_text(encoding='utf-8')
        self.assertIn('"attempt-reconnect"', hook)

    def test_applications_started_only_after_ready(self):
        code = (SRC / 'MainForm.cs').read_text(encoding='utf-8')
        self.assertIn('LaunchGate.CanLaunch(status,alive) && !stopRequested && !launched', code)
        self.assertIn('info.ArgumentList.Add(c.Rdp)', code)
        self.assertIn('if(c.AutoRdp)LaunchApp(false);if(c.AutoTrueConf)LaunchApp(true)', code)

    def test_utf8_bom_for_windows_powershell(self):
        self.assertTrue((SRC / 'Network.ps1').read_bytes().startswith(b'\xef\xbb\xbf'))

    def test_native_mtu_and_no_runtime_self_diagnostics(self):
        script = (SRC / 'Network.ps1').read_text(encoding='utf-8-sig')
        self.assertIn(').NlMtu;', script)
        self.assertNotIn(').NlMtuBytes', script)
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        for removed in ('AddMinutes(', 'Preflight', 'work-check.json', 'refresh='):
            self.assertNotIn(removed, worker)
        ui = (SRC / 'MainForm.cs').read_text(encoding='utf-8')
        self.assertNotIn('CheckInternet', ui)
        self.assertNotIn('Get-DnsClientNrptPolicy', script)
        self.assertNotIn('Existing DNS policy overlaps work names', script)

    def test_no_unsafe_tls_options(self):
        code = '\n'.join(p.read_text(encoding='utf-8-sig') for p in SRC.glob('*.cs'))
        for forbidden in ('DangerousAcceptAnyServerCertificateValidator', '--no-system-trust', '--servercert', '--dump-http-traffic'):
            self.assertNotIn(forbidden, code)

    def test_rdp_endpoint_does_not_gate_vpn(self):
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertNotIn('Reachable(', worker)
        self.assertNotIn('ProbeHost', worker)
        self.assertNotIn('RdpEndpointReachable', worker)

if __name__ == '__main__':
    unittest.main()
