using System.Diagnostics;

namespace FortiSplit.Work;

internal sealed partial class MainForm
{
    private static Color WorkBackground => SystemInformation.HighContrast ? SystemColors.Window : Color.FromArgb(244, 247, 251);
    private static Color WorkText => SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(26, 42, 62);
    private static Color WorkMuted => SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(75, 91, 112);
    private static Color WorkAccent => SystemInformation.HighContrast ? SystemColors.HotTrack : Color.FromArgb(17, 86, 160);
    private static readonly Font MetricSmallFont = new("Segoe UI", 9);
    private static readonly Font MetricVolumeFont = new("Segoe UI", 11, FontStyle.Bold);
    private static readonly Font MetricTotalFont = new("Segoe UI", 16, FontStyle.Bold);

    private readonly Label trafficTitle = new() { Text = "Трафик VPN за сеанс", AutoSize = true, Visible = false, Margin = new Padding(0, 18, 0, 7) };
    private readonly TableLayoutPanel trafficOverview = new() { Name = "vpn-traffic", AccessibleName = "Общий трафик VPN", Visible = false, Height = 82, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
    private readonly Label trafficUnavailable = new() { Text = "Статистика VPN недоступна.", AutoSize = true, Visible = false, Margin = new Padding(0, 4, 0, 4) };
    private readonly MetricCell vpnReceived = new("Получено");
    private readonly MetricCell vpnSent = new("Отправлено");
    private readonly TableLayoutPanel peerHeading = new() { Visible = false, Height = 43, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 16, 0, 0) };
    private readonly Label peerScope = new() { AutoSize = true, Visible = false, Margin = new Padding(0, 2, 0, 10) };
    private readonly TableLayoutPanel peerColumns = ThreeColumns(height: 33);
    private readonly Label peerEmpty = new() { AutoSize = true, Visible = false, Margin = new Padding(0, 4, 0, 4) };
    private readonly TableLayoutPanel activityHistory = new() { Name = "work-activity-history", Visible = false, AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1, Margin = new Padding(0, 16, 0, 0) };
    private readonly (Control Row, Label Address, Label Time)[] historyRows = new (Control, Label, Label)[TunnelActivity.HistoryLimit];
    private WorkActivityEvent[] lastActivityEvents = [];
    private readonly Button connectionCheck = Btn("Проверить адрес…");
    private readonly Dictionary<string, PeerRow> peerRows = new(StringComparer.Ordinal);
    private FlowLayoutPanel workContent = null!;
    private Control[] trafficSections = [];

    private void BuildWorkView(FlowLayoutPanel main)
    {
        workContent = main;
        main.BackColor = WorkBackground;
        state.ForeColor = WorkText;
        detail.ForeColor = WorkMuted;
        duration.ForeColor = WorkMuted;
        trafficTitle.ForeColor = WorkText;
        trafficTitle.Font = new Font(Font, FontStyle.Bold);
        trafficUnavailable.ForeColor = peerScope.ForeColor = peerEmpty.ForeColor = WorkMuted;

        trafficOverview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        trafficOverview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        trafficOverview.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        vpnReceived.Margin = new Padding(0, 0, 5, 0);
        vpnSent.Margin = new Padding(5, 0, 0, 0);
        trafficOverview.Controls.Add(vpnReceived, 0, 0);
        trafficOverview.Controls.Add(vpnSent, 1, 0);

        peerHeading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        peerHeading.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 164));
        peerHeading.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var title = new Label { Text = "Рабочие адреса", ForeColor = WorkText, Font = new Font(Font, FontStyle.Bold), Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Margin = Padding.Empty };
        connectionCheck.Name = "check-work-address";
        connectionCheck.Dock = DockStyle.Fill;
        connectionCheck.Margin = new Padding(0, 3, 0, 4);
        connectionCheck.BackColor = SystemColors.Window;
        connectionCheck.ForeColor = WorkAccent;
        connectionCheck.FlatAppearance.BorderColor = WorkAccent;
        connectionCheck.Click += (_, _) => Try(() => CheckWorkConnection());
        peerHeading.Controls.Add(title, 0, 0);
        peerHeading.Controls.Add(connectionCheck, 1, 0);
        peerScope.Text = $"Активность за {TunnelActivity.RecentSeconds} с · объём за сеанс";

        peerColumns.Name = "vpn-active-addresses";
        peerColumns.Visible = false;
        peerColumns.BackColor = SystemInformation.HighContrast ? SystemColors.Control : Color.FromArgb(227, 235, 246);
        string[] captions = ["Адрес", "Приём", "Отправка"];
        for (int column = 0; column < captions.Length; column++)
            peerColumns.Controls.Add(new Label { Text = captions[column], ForeColor = WorkText, Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(12, 0, 3, 0), Font = new Font(Font.Name, 9, FontStyle.Bold) }, column, 0);
        peerColumns.SizeChanged += (_, _) =>
        {
            foreach (var row in peerRows.Values) row.Width = peerColumns.Width;
        };

        var workStatus = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 2, RowCount = 3, Margin = Padding.Empty };
        workStatus.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        workStatus.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 156));
        for (int row = 0; row < 3; row++) workStatus.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        connect.Dock = DockStyle.Fill;
        connect.Margin = new Padding(0, 5, 0, 2);
        state.Margin = new Padding(0, 0, 8, 3);
        workStatus.Controls.Add(state, 0, 0);
        workStatus.Controls.Add(connect, 1, 0);
        workStatus.Controls.Add(duration, 0, 1);
        workStatus.Controls.Add(detail, 0, 2);
        workStatus.SetColumnSpan(detail, 2);
        trafficSections = [trafficTitle, trafficOverview, trafficUnavailable, peerHeading, peerScope, peerColumns];
        BuildActivityHistory();
        main.Controls.AddRange([workStatus, .. trafficSections, peerEmpty, activityHistory, updateBanner]);
        void FitStatus()
        {
            int width = Math.Max(120, main.ClientSize.Width - main.Padding.Horizontal);
            if (workStatus.MinimumSize.Width != width) workStatus.MinimumSize = new Size(width, 0);
            if (activityHistory.MinimumSize.Width != width) activityHistory.MinimumSize = new Size(width, 0);
        }
        main.ClientSizeChanged += (_, _) => FitStatus();
        FitStatus();
        FillWidth(main, workStatus);
        foreach (var control in new Control[] { trafficOverview, peerHeading, peerColumns }) FillWidth(main, control);
        foreach (var label in new[] { state, detail, duration, trafficUnavailable, peerScope, peerEmpty, updateBanner }) ConstrainText(main, label);
        StyleConnectionButton(false);
    }

    private void BuildActivityHistory()
    {
        activityHistory.RowCount = historyRows.Length + 1;
        activityHistory.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        activityHistory.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        activityHistory.Controls.Add(new Label { Text = "Последние события", AutoSize = true, ForeColor = WorkText,
            Font = MetricVolumeFont, Margin = new Padding(0, 0, 0, 8) }, 0, 0);
        for (int i = 0; i < historyRows.Length; i++)
        {
            var row = new TableLayoutPanel { Height = 56, Dock = DockStyle.Top, ColumnCount = 1, RowCount = 2,
                BackColor = SystemColors.Window, Padding = new Padding(12, 4, 8, 4), Margin = new Padding(0, 0, 0, 3) };
            row.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            row.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            var address = MetricLabel(MetricVolumeFont);
            var time = MetricLabel();
            row.Controls.Add(address, 0, 0);
            row.Controls.Add(time, 0, 1);
            historyRows[i] = (row, address, time);
            activityHistory.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            activityHistory.Controls.Add(row, 0, i + 1);
        }
    }

    private void ShowActivityHistory()
    {
        for (int i = 0; i < historyRows.Length; i++)
        {
            var (row, address, time) = historyRows[i];
            row.Visible = i < lastActivityEvents.Length;
            if (i >= lastActivityEvents.Length) continue;
            var item = lastActivityEvents[i];
            address.Text = item.Peer.Display;
            time.Text = ActivityCaption(item.Activity);
        }
        activityHistory.Visible = lastActivityEvents.Length > 0;
        int index = workContent.Controls.GetChildIndex(activityHistory);
        int anchor = workContent.Controls.GetChildIndex(peerEmpty);
        int target = index > anchor ? anchor + 1 : anchor;
        if (index != target) workContent.Controls.SetChildIndex(activityHistory, target);
    }

    private static string ActivityCaption(WorkActivityInterval activity)
    {
        var elapsed = activity.Duration;
        string duration = $"{(long)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}";
        return $"Начало {activity.StartedUtc.ToLocalTime():dd.MM.yy HH:mm:ss} · Последняя активность {activity.LastActivityUtc.ToLocalTime():dd.MM.yy HH:mm:ss} · Длительность {duration}";
    }

    private void SetTrafficSummary(TrafficSample? sample)
    {
        trafficOverview.Visible = sample is not null;
        trafficUnavailable.Visible = sample is null;
        if (sample is not null)
        {
            vpnReceived.Update(sample.Received, sample.ReceiveRate);
            vpnSent.Update(sample.Sent, sample.SendRate);
        }
    }

    private void StyleConnectionButton(bool stopsSession)
    {
        connect.BackColor = stopsSession ? SystemColors.Window : SystemInformation.HighContrast ? SystemColors.Highlight : WorkAccent;
        connect.ForeColor = stopsSession ? WorkText : SystemColors.HighlightText;
        connect.FlatAppearance.BorderColor = stopsSession ? WorkMuted : connect.BackColor;
    }

    private void ShowPeerTraffic(WorkTrafficSnapshot? snapshot, long now)
    {
        bool delayed = snapshot is { Peers.Length: > 0 } && Stopwatch.GetElapsedTime(snapshot.Timestamp, now).TotalSeconds > 3;
        var peers = delayed ? [] : snapshot?.Peers ?? [];
        var visible = peers.Select(peer => peer.Peer.Address).ToHashSet(StringComparer.Ordinal);
        workContent.SuspendLayout();
        try
        {
            peerColumns.Visible = peers.Length > 0;
            peerEmpty.Visible = peers.Length == 0;
            // Showing previously hidden WinForms controls can alter the native child order.
            for (int section = 0; section < trafficSections.Length; section++)
                if (workContent.Controls.GetChildIndex(trafficSections[section]) != section + 1)
                    workContent.Controls.SetChildIndex(trafficSections[section], section + 1);
            foreach (string address in peerRows.Keys.Where(address => !visible.Contains(address)).ToArray())
            {
                var row = peerRows[address];
                peerRows.Remove(address);
                row.Dispose();
            }
            int index = workContent.Controls.GetChildIndex(peerColumns) + 1;
            foreach (var item in peers)
            {
                string address = item.Peer.Address;
                if (!peerRows.TryGetValue(address, out var row))
                {
                    row = new PeerRow(() => Try(() => CheckWorkConnection(address))) { Width = peerColumns.Width };
                    peerRows.Add(address, row);
                    workContent.Controls.Add(row);
                }
                if (workContent.Controls.GetChildIndex(row) != index) workContent.Controls.SetChildIndex(row, index);
                index++;
                row.Update(item);
            }
            peerEmpty.Text = delayed ? "Обновляем статистику по адресам…" : snapshot is not { CaptureAvailable: true }
                ? "Статистика по адресам недоступна." : "За это время трафика по рабочим адресам не было.";
        }
        finally { workContent.ResumeLayout(); }
    }

    private static TableLayoutPanel ThreeColumns(int height)
    {
        var grid = new TableLayoutPanel { ColumnCount = 3, RowCount = 1, Height = height, Margin = Padding.Empty };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        return grid;
    }

    private static Label MetricLabel(Font? font = null) => new()
        { Dock = DockStyle.Fill, AutoEllipsis = true, ForeColor = font is null ? WorkMuted : WorkText, Margin = Padding.Empty,
          TextAlign = ContentAlignment.MiddleLeft, Font = font ?? MetricSmallFont };

    private sealed class MetricCell : TableLayoutPanel
    {
        private readonly Label volume;
        private readonly Label rate = MetricLabel();

        internal MetricCell(string? title = null)
        {
            bool overview = title is not null;
            volume = MetricLabel(overview ? MetricTotalFont : MetricVolumeFont);
            Dock = DockStyle.Fill;
            BackColor = SystemColors.Window;
            Margin = Padding.Empty;
            Padding = new Padding(12, 6, 6, 6);
            ColumnCount = 1;
            RowCount = overview ? 3 : 2;
            int row = 0;
            if (title is not null)
            {
                var caption = MetricLabel();
                caption.Text = title;
                RowStyles.Add(new RowStyle(SizeType.Percent, 28));
                Controls.Add(caption, 0, row++);
            }
            RowStyles.Add(new RowStyle(SizeType.Percent, overview ? 43 : 55));
            RowStyles.Add(new RowStyle(SizeType.Percent, overview ? 29 : 45));
            Controls.Add(volume, 0, row++);
            Controls.Add(rate, 0, row);
        }

        internal void Update(long bytes, double? bytesPerSecond)
        {
            volume.Text = FormatTraffic(bytes);
            rate.Text = bytesPerSecond is double speed ? FormatTraffic(speed) + "/с" : "—";
        }
    }

    private sealed class PeerRow : Panel
    {
        private readonly LinkLabel addressLink = new() { Dock = DockStyle.Fill, AutoEllipsis = true, Margin = Padding.Empty,
            TextAlign = ContentAlignment.MiddleLeft, LinkBehavior = LinkBehavior.HoverUnderline, LinkColor = WorkAccent,
            ActiveLinkColor = WorkAccent, VisitedLinkColor = WorkAccent };
        private readonly Label addressCaption = MetricLabel();
        private readonly MetricCell received = new();
        private readonly MetricCell sent = new();
        private readonly Label activity = MetricLabel();

        internal PeerRow(Action check)
        {
            Height = 57;
            Margin = new Padding(0, 0, 0, 2);
            BackColor = SystemColors.Window;
            var columns = ThreeColumns(57);
            columns.Dock = DockStyle.Fill;
            var identity = new TableLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty, Padding = new Padding(12, 6, 6, 6), ColumnCount = 1, RowCount = 2 };
            identity.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            identity.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            identity.Controls.Add(addressLink, 0, 0);
            identity.Controls.Add(addressCaption, 0, 1);
            addressLink.LinkClicked += (_, _) => check();
            columns.Controls.Add(identity, 0, 0);
            columns.Controls.Add(received, 1, 0);
            columns.Controls.Add(sent, 2, 0);
            var content = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 57));
            content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            activity.Margin = new Padding(12, 0, 8, 3);
            content.Controls.Add(columns, 0, 0);
            content.Controls.Add(activity, 0, 1);
            Controls.Add(content);
        }

        internal void Update(WorkPeerTraffic value)
        {
            var peer = value.Peer;
            string label = peer.Hosts.Length > 0 ? string.Join(", ", peer.Hosts) : peer.Address;
            if (addressLink.Text != label) addressLink.Text = label;
            addressLink.AccessibleName = $"Проверить {peer.Display}";
            addressCaption.Text = peer.Hosts.Length > 0 ? peer.Address : string.Empty;
            received.Update(value.Received, value.ReceiveRate);
            sent.Update(value.Sent, value.SendRate);
            activity.Visible = value.Activity is not null;
            Height = value.Activity is null ? 57 : 78;
            if (value.Activity is { } timing) activity.Text = ActivityCaption(timing);
        }
    }
}
