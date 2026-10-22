using System.Text.Json;

namespace FortiSplit.Companion;

internal static class SelfTests
{
    internal static int Run(string report, string screenshot)
    {
        var checks = new Dictionary<string, bool>();
        var directory = Path.Combine(Path.GetTempPath(), "forti-companion-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var run = new WorkplaceRun(); var now = DateTimeOffset.UtcNow;
            checks["idle_by_default"] = run.Phase == RunPhase.Idle && !run.Confirm(Guid.Empty);
            var id = run.Begin(now);
            checks["one_intent"] = id == run.Begin(now) && run.Phase == RunPhase.Waiting;
            checks["no_foreign_confirmation"] = !run.Confirm(Guid.NewGuid());
            checks["launch_once"] = run.Confirm(id) && !run.Confirm(id);
            checks["ready_does_not_expire"] = !run.Expire(now.AddDays(1));
            run.Cancel(); checks["cancel_invalidates_callbacks"] = !run.Confirm(id) && run.Phase == RunPhase.Idle;
            id = run.Begin(now); checks["new_run_new_id"] = id != Guid.Empty;
            checks["bounded_wait"] = run.Expire(now.AddMinutes(6)) && !run.Confirm(id);
            checks["no_blind_reconnect"] = run.Phase == RunPhase.Idle;
            for (int bits = 0; bits < 32; bits++)
                checks["eligibility_" + bits] = WorkplaceRun.Eligible((bits & 1) != 0, (bits & 2) != 0,
                    (bits & 4) != 0, (bits & 8) != 0, (bits & 16) != 0) == (bits == 31);
            var valid = new WorkplaceSettings
            { SetupComplete = true, FortiPath = Path.Combine(directory, "FortiClient.exe"), AdapterId = "synthetic-adapter", ProbeAddress = "10.77.1.20" };
            File.WriteAllBytes(valid.FortiPath, [0]); // Never executed.
            bool Reject(Action action) { try { action(); return false; } catch { return true; } }
            checks["default_apps_off"] = !valid.LaunchRdp && !valid.LaunchTrueConf;
            checks["rdp_url_rejected"] = Reject(() => WorkplaceSettings.ValidatePath("https://example.com/a.rdp", ".rdp"));
            checks["unc_rejected"] = Reject(() => WorkplaceSettings.ValidatePath(@"\\server\share\a.rdp", ".rdp"));
            checks["command_rejected"] = Reject(() => WorkplaceSettings.ValidatePath("cmd.exe /c calc", ".exe"));
            checks["wrong_extension_rejected"] = Reject(() => WorkplaceSettings.ValidatePath(Path.Combine(directory, "a.cmd"), ".rdp"));
            checks["enabled_rdp_requires_file"] = Reject(() => (valid with { LaunchRdp = true }).Validate());
            checks["enabled_trueconf_requires_file"] = Reject(() => (valid with { LaunchTrueConf = true }).Validate());
            checks["bad_port_rejected"] = Reject(() => (valid with { ProbePort = 0 }).Validate());
            checks["ipv6_rejected"] = Reject(() => (valid with { ProbeAddress = "::1" }).Validate());
            checks["loopback_rejected"] = Reject(() => (valid with { ProbeAddress = "127.0.0.1" }).Validate());
            checks["multicast_rejected"] = Reject(() => (valid with { ProbeAddress = "224.0.0.1" }).Validate());
            checks["missing_adapter_rejected"] = Reject(() => (valid with { AdapterId = "" }).Validate());
            var store = new SettingsStore(Path.Combine(directory, "private settings"));
            store.Save(valid); checks["private_settings_roundtrip"] = store.Load() == valid;
            File.WriteAllText(store.FilePath, "{\"Schema\":1,\"Schema\":2}");
            checks["duplicate_json_rejected"] = Reject(() => store.Load());
            File.WriteAllText(store.FilePath, "{\"UnexpectedCommand\":\"cmd.exe\"}");
            checks["unknown_fields_rejected"] = Reject(() => store.Load());
            File.WriteAllText(store.FilePath, new string(' ', 65537));
            checks["bounded_settings_read"] = Reject(() => store.Load());
            store.Save(valid);
            using var form = new MainForm(store, testMode: true, initial: valid);
            checks["two_native_tabs"] = form.TestHasTabs;
            checks["ui_does_not_start_vpn_or_apps"] = form.TestSafeDefaults;
            form.TestLayout(screenshot);
            checks["native_ui_rendered"] = File.Exists(screenshot) && new FileInfo(screenshot).Length > 1000;
            using var firstRun = new MainForm(store, testMode: true, initial: valid with { SetupComplete = false });
            checks["wizard_options_and_settings_restore"] = firstRun.TestWizard();
        }
        catch (Exception error) { checks["unexpected_" + error.GetType().Name] = false; }
        finally { Directory.Delete(directory, true); } // Only this test's freshly created temp directory.
        var result = new
        {
            schema = 1, version = "0.1.0", platform = "Windows", architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            runtime = Environment.Version.ToString(), checks, successful = checks.Values.All(x => x),
            route_engine = "none — companion only", real_vpn_acceptance = "pending", authenticode = false,
            no_real_vpn_or_login_registration_in_tests = true
        };
        File.WriteAllText(report, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        return result.successful ? 0 : 1;
    }
}
