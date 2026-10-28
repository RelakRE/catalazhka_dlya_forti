from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'FortiSplit.Work'

class WorkSafety(unittest.TestCase):
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
        self.assertIn('65536', ipc)
        ui = (SRC / 'MainForm.Auth.cs').read_text(encoding='utf-8')
        self.assertIn('PipeOptions.CurrentUserOnly', ui)
        self.assertIn('VerifyClient(server,workerPid)', ui)
        self.assertIn('request.Kind=="authenticated"', ui)

    def test_independent_cleanup_and_owned_process(self):
        code = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertIn('"--watch",id', code)
        self.assertIn('owner.WaitForExit()', code)
        self.assertIn('child.StartTime.ToUniversalTime().Ticks!=vpnTicks', code)
        self.assertIn('child.MainModule?.FileName', code)
        self.assertNotIn('GetProcessesByName("Forti', code)
        self.assertNotIn('Kill(true)', code)

    def test_dns_is_outside_synchronous_hook(self):
        code = (SRC / 'Network.ps1').read_text(encoding='utf-8-sig')
        hook = code.split("if ($Mode -eq 'Hook') {", 1)[1].split('$script:state=Read-State', 1)[0]
        self.assertNotIn('Resolve-DnsName', hook)
        self.assertNotIn('Add-DnsClientNrptRule', hook)

    def test_applications_started_only_after_ready(self):
        code = (SRC / 'MainForm.cs').read_text(encoding='utf-8')
        self.assertIn('LaunchGate.CanLaunch(status,alive) && !stopRequested && !launched', code)
        self.assertIn('info.ArgumentList.Add(c.Rdp)', code)
        self.assertIn('if(c.AutoRdp)LaunchApp(false);if(c.AutoTrueConf)LaunchApp(true)', code)

    def test_utf8_bom_for_windows_powershell(self):
        self.assertTrue((SRC / 'Network.ps1').read_bytes().startswith(b'\xef\xbb\xbf'))

    def test_native_mtu_property_and_hook_failure_propagation(self):
        script = (SRC / 'Network.ps1').read_text(encoding='utf-8-sig')
        self.assertIn(').NlMtu;', script)
        self.assertNotIn(').NlMtuBytes', script)
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        loop = worker.split('while(!vpn.HasExited', 1)[1]
        self.assertLess(loop.index('network-error.txt'), loop.index('if(File.Exists(path))'))

    def test_no_unsafe_tls_options(self):
        code = '\n'.join(p.read_text(encoding='utf-8-sig') for p in SRC.glob('*.cs'))
        for forbidden in ('DangerousAcceptAnyServerCertificateValidator', '--no-system-trust', '--servercert', '--dump-http-traffic'):
            self.assertNotIn(forbidden, code)

    def test_rdp_endpoint_does_not_gate_vpn(self):
        worker = (SRC / 'Worker.cs').read_text(encoding='utf-8')
        self.assertNotIn('Reachable(', worker)
        self.assertNotIn('ProbeHost', worker)
        self.assertIn('RdpPrecheck="disabled"', worker)

if __name__ == '__main__':
    unittest.main()
