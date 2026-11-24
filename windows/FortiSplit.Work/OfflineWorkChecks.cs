using System.Diagnostics;
using System.Net;

namespace FortiSplit.Work;

internal static class OfflineWorkChecks
{
    internal static void CheckDiagnosticCancellation(Dictionary<string, bool> checks)
    {
        var network = new WorkNetwork(Guid.Empty.ToString(), 0, "192.0.2.20", "ready",
            [new("desktop.example.com", ["192.0.2.10"])]);
        bool sessionReady = true;
        CancellationToken token = default;
        bool started = false;
        int? selectedPort = null;
        async Task<WorkConnectionResult> Probe(WorkNetwork state, IPAddress address, int? port, CancellationToken cancellation)
        {
            started = state == network && address.ToString() == "192.0.2.10";
            selectedPort = port;
            token = cancellation;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellation);
            return new("Через VPN");
        }

        using (var dialog = new WorkConnectionDialog(network, () => sessionReady, "desktop.example.com", Probe))
        {
            dialog.Show();
            Application.DoEvents();
            checks["work_diagnostic_waits_for_explicit_check"] = !started;
            dialog.AcceptButton!.PerformClick();
            PumpUntil(() => started);
            checks["work_diagnostic_default_probes_without_tcp"] = started && selectedPort is null;
            dialog.Close();
            Application.DoEvents();
            checks["work_diagnostic_close_cancels_probe"] = started && token.IsCancellationRequested;
        }

        started = false;
        token = default;
        using (var dialog = new WorkConnectionDialog(network, () => sessionReady, "desktop.example.com", Probe))
        {
            dialog.Show();
            var mode = dialog.Controls.Find("diagnostic-mode", true).OfType<ComboBox>().Single();
            mode.SelectedIndex = mode.FindStringExact("Шлюз RDP (443)");
            dialog.AcceptButton!.PerformClick();
            PumpUntil(() => started);
            checks["work_diagnostic_gateway_preset_selects_443"] = started && selectedPort == 443;
            sessionReady = false;
            var result = dialog.Controls.Find("diagnostic-result", true).OfType<Label>().Single();
            PumpUntil(() => result.Text.StartsWith("VPN-сеанс изменился", StringComparison.Ordinal));
            checks["work_diagnostic_disconnect_cancels_probe"] = started && token.IsCancellationRequested &&
                result.Text.StartsWith("VPN-сеанс изменился", StringComparison.Ordinal);
        }
    }

    private static void PumpUntil(Func<bool> complete)
    {
        long started = Stopwatch.GetTimestamp();
        while (!complete() && Stopwatch.GetElapsedTime(started).TotalSeconds < 3)
        {
            Application.DoEvents();
            Thread.Sleep(10);
        }
    }
}

internal sealed partial class MainForm
{
    internal void CheckConnectedSettings(Dictionary<string, bool> checks)
    {
        var savedStatus = status;
        using var fixture = Process.GetCurrentProcess();
        worker = fixture;
        try
        {
            status = new("connected", "VPN подключён.", true);
            RefreshUi();
            checks["settings_connected_keeps_addresses_editable"] = settingsContext.Visible && saveSettings.Enabled &&
                saveSettings.Text == "Применить рабочие адреса" && workAddressInput.Enabled && dnsDomains.Enabled && checkWorkAddress.Enabled;
            checks["settings_connected_locks_connection_and_app_fields"] = !server.Enabled && !user.Enabled && !rdp.Enabled;
        }
        finally { worker = null; status = savedStatus; RefreshUi(); }
    }

    internal void CheckPeerTrafficView(Dictionary<string, bool> checks)
    {
        var first = new WorkPeerTraffic(new("192.0.2.10", ["desktop.example.com"]), 1200, 350, 450, 210);
        var second = new WorkPeerTraffic(new("192.0.2.11", ["gateway.example.com"]), 8900, 800, 1100, 0);
        var started = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var activity = new WorkActivityInterval(started, started.AddSeconds(26), TimeSpan.FromSeconds(26));
        first = first with { Activity = activity };
        WorkActivityEvent[] history = [new(second.Peer, activity)];
        var savedStatus = status;
        var savedHistory = lastActivityEvents;
        using var fixture = Process.GetCurrentProcess();
        worker = fixture;
        try
        {
            long now = Stopwatch.GetTimestamp();
            status = new("connected", "VPN подключён.", true, WorkTraffic: new(now, [first, second], history));
            RefreshUi();
            SetTrafficSummary(new(10100, 1150, 1550, 210));
            ShowPeerTraffic(status.WorkTraffic, now);
            Application.DoEvents();
            var firstRow = peerRows[first.Peer.Address];
            var secondRow = peerRows[second.Peer.Address];
            checks["work_view_displays_independent_volume_and_rate_by_ip"] = peerColumns.Visible &&
                Labels(firstRow).Contains(FormatTraffic(first.Received)) && Labels(firstRow).Contains("210 Б/с") &&
                Labels(secondRow).Contains(FormatTraffic(second.Received)) && Labels(secondRow).Contains("0 Б/с");
            checks["work_view_places_session_summary_above_address_table"] = trafficOverview.Visible &&
                trafficTitle.Bottom <= trafficOverview.Top && trafficOverview.Bottom <= peerHeading.Top && peerHeading.Bottom <= peerColumns.Top;
            checks["work_view_shows_activity_times_and_history_below_active_rows"] =
                Labels(firstRow).Any(text => text.Contains("Длительность 00:00:26", StringComparison.Ordinal)) &&
                activityHistory.Visible && activityHistory.Top >= secondRow.Bottom && historyRows[0].Address.Text == second.Peer.Display;
            ShowPeerTraffic(new(now, [first with { Received = 3300 }]), now);
            checks["work_view_keeps_active_row_and_removes_expired_address"] = peerRows.Count == 1 &&
                ReferenceEquals(firstRow, peerRows[first.Peer.Address]) && Labels(firstRow).Contains(FormatTraffic(3300)) && secondRow.IsDisposed;
            worker = null;
            status = new("disconnected", "VPN отключён.", WorkTraffic: new(now, [], history, CaptureAvailable: false));
            RefreshUi();
            checks["work_view_keeps_completed_activity_after_disconnect"] = !peerColumns.Visible && activityHistory.Visible &&
                historyRows[0].Time.Text.Contains("Длительность 00:00:26", StringComparison.Ordinal);
        }
        finally { worker = null; status = savedStatus; lastActivityEvents = savedHistory; RefreshUi(); }

        static IEnumerable<string> Labels(Control control) => control.Controls.Cast<Control>()
            .SelectMany(child => child is Label label ? [label.Text] : Labels(child));
    }
}
