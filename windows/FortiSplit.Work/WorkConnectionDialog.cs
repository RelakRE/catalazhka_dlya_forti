using System.Net;
using System.Net.NetworkInformation;

namespace FortiSplit.Work;

internal sealed class WorkConnectionDialog : Form
{
    private sealed record ProbeMode(string Name, int? Port = null, bool Custom = false);

    private readonly ComboBox destination = new() { Name = "diagnostic-address", AccessibleName = "Рабочий адрес или IPv4", Dock = DockStyle.Fill, MaxLength = 253 };
    private readonly ComboBox mode = new() { Name = "diagnostic-mode", AccessibleName = "Что проверить", Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList, DisplayMember = nameof(ProbeMode.Name) };
    private readonly NumericUpDown port = new() { Name = "diagnostic-port", AccessibleName = "TCP-порт", Minimum = 1, Maximum = 65535, Value = 443, Dock = DockStyle.Fill };
    private readonly Label portLabel = new() { Text = "TCP-порт", AutoSize = true, Margin = new Padding(3, 10, 3, 3) };
    private readonly Button check = new() { Text = "Проверить", AutoSize = true, BackColor = SystemColors.Highlight, ForeColor = SystemColors.HighlightText, FlatStyle = FlatStyle.Flat };
    private readonly Button close = new() { Text = "Закрыть", AutoSize = true, DialogResult = DialogResult.Cancel };
    private readonly Label result = new() { Name = "diagnostic-result", AccessibleName = "Состояние проверки", Dock = DockStyle.Fill };
    private readonly Label routeResult = ResultLabel("diagnostic-route", "Маршрут Windows");
    private readonly Label routeDetails = ResultLabel("diagnostic-route-details", "Параметры маршрута");
    private readonly Label pingResult = ResultLabel("diagnostic-ping", "Результат пинга");
    private readonly Label tcpResult = ResultLabel("diagnostic-tcp", "Результат проверки порта");
    private CancellationTokenSource? running;

    internal WorkConnectionDialog(WorkNetwork network, Func<bool> sessionReady, string? selectedHost,
        Func<WorkNetwork, IPAddress, int?, CancellationToken, Task<WorkConnectionResult>>? probe = null)
    {
        probe ??= WorkConnectionCheck.Run;
        Text = "Проверка рабочего адреса";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = MaximizeBox = ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Font;
        Font = new Font("Segoe UI", 11);
        ClientSize = new Size(560, 390);

        var peers = network.Peers();
        if (selectedHost is not null)
        {
            peers = peers.Where(peer => peer.Address.Equals(selectedHost, StringComparison.Ordinal) ||
                peer.Hosts.Contains(selectedHost, StringComparer.OrdinalIgnoreCase)).ToArray();
            if (peers.Length == 0) destination.Text = selectedHost;
        }
        destination.DisplayMember = nameof(WorkPeer.Display);
        destination.Items.AddRange(peers);
        if (selectedHost is not null && peers.Length == 1) destination.SelectedIndex = 0;
        mode.Items.AddRange([
            new ProbeMode("Маршрут и пинг"),
            new ProbeMode("Шлюз RDP (443)", 443),
            new ProbeMode("Прямой RDP (3389)", 3389),
            new ProbeMode("Веб-сайт HTTPS (443)", 443),
            new ProbeMode("Веб-сайт HTTP (80)", 80),
            new ProbeMode("Другой TCP-порт", Custom: true)
        ]);
        mode.SelectedIndex = 0;

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), RowCount = 7, ColumnCount = 2 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 76));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 24));
        for (int row = 0; row < 4; row++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        AddWide(new Label { Text = "Куда", AutoSize = true }, 0);
        AddWide(destination, 1);
        layout.Controls.Add(new Label { Text = "Что проверить", AutoSize = true, Margin = new Padding(3, 10, 3, 3) }, 0, 2);
        layout.Controls.Add(portLabel, 1, 2);
        layout.Controls.Add(mode, 0, 3);
        layout.Controls.Add(port, 1, 3);

        var values = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(10), Margin = new Padding(3, 12, 3, 6), ColumnCount = 2, RowCount = 4, BackColor = SystemColors.Window };
        values.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 115));
        values.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int row = 0; row < 4; row++) values.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        AddValue("Маршрут", routeResult, 0);
        values.Controls.Add(routeDetails, 1, 1);
        routeDetails.ForeColor = SystemColors.GrayText;
        AddValue("Пинг (ICMP)", pingResult, 2);
        AddValue("TCP-порт", tcpResult, 3);
        AddWide(values, 4);
        AddWide(result, 5);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.AddRange([check, close]);
        AddWide(buttons, 6);
        Controls.Add(layout);
        AcceptButton = check;
        CancelButton = close;

        check.Click += async (_, _) => await Run(network, sessionReady, probe);
        destination.TextChanged += (_, _) => ResetResults();
        mode.SelectedIndexChanged += (_, _) => ResetResults();
        port.ValueChanged += (_, _) => ResetResults();
        FormClosing += (_, _) => running?.Cancel();
        ResetResults();
        if (selectedHost is not null && peers.Length > 1) result.Text = "У этого имени несколько IPv4. Выберите адрес.";
        else if (selectedHost is not null && peers.Length == 0 && !IPAddress.TryParse(selectedHost, out _))
            result.Text = "У имени пока нет IPv4. Примените рабочие адреса и дождитесь обновления.";

        void AddWide(Control control, int row)
        {
            layout.Controls.Add(control, 0, row);
            layout.SetColumnSpan(control, 2);
        }

        void AddValue(string caption, Label value, int row)
        {
            values.Controls.Add(new Label { Text = caption, AutoSize = true, Margin = new Padding(0, 3, 3, 4) }, 0, row);
            values.Controls.Add(value, 1, row);
        }
    }

    private static Label ResultLabel(string name, string accessibleName) => new()
        { Name = name, AccessibleName = accessibleName, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 3, 0, 4) };

    private void ResetResults()
    {
        bool customPort = mode.SelectedItem is ProbeMode { Custom: true };
        portLabel.Visible = port.Visible = customPort;
        if (mode.Parent is TableLayoutPanel layout) layout.SetColumnSpan(mode, customPort ? 1 : 2);
        SetResults(null);
        result.Text = string.IsNullOrWhiteSpace(destination.Text) ? "Выберите рабочий адрес или введите IPv4." : "";
    }

    private void SetResults(WorkConnectionResult? value)
    {
        routeResult.Text = value?.Route ?? "—";
        routeDetails.Text = value?.RouteDetails ?? "";
        routeDetails.Visible = value?.RouteDetails is not null;
        pingResult.Text = value?.Ping ?? (value is null ? "—" : "Не выполнялся");
        tcpResult.Text = value?.Tcp ?? (value is null ? "—" : "Не проверялся");
    }

    private async Task Run(WorkNetwork network, Func<bool> sessionReady,
        Func<WorkNetwork, IPAddress, int?, CancellationToken, Task<WorkConnectionResult>> probe)
    {
        if (running is not null) return;
        if (!sessionReady()) { result.Text = "VPN-сеанс изменился. Откройте проверку заново."; return; }
        string input = destination.Text.Trim();
        string address = destination.SelectedItem is WorkPeer peer && input == peer.Display ? peer.Address : input;
        try { Config.IPv4(address); }
        catch (ArgumentException)
        {
            result.Text = "Выберите адрес из списка или введите IPv4.";
            return;
        }

        using var cancellation = new CancellationTokenSource();
        using var monitor = new System.Windows.Forms.Timer { Interval = 100 };
        monitor.Tick += (_, _) => { if (!sessionReady()) cancellation.Cancel(); };
        running = cancellation;
        check.Enabled = destination.Enabled = mode.Enabled = port.Enabled = false;
        SetResults(null);
        result.Text = "Проверяем связь…";
        try
        {
            monitor.Start();
            var selectedMode = (ProbeMode)mode.SelectedItem!;
            var report = await probe(network, IPAddress.Parse(address), selectedMode.Custom ? (int)port.Value : selectedMode.Port, cancellation.Token);
            if (!cancellation.IsCancellationRequested && !IsDisposed)
            {
                bool current = sessionReady();
                if (current) SetResults(report);
                result.Text = current ? report.Notice ?? "" : "VPN-сеанс изменился. Откройте проверку заново.";
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            if (!IsDisposed && !sessionReady()) result.Text = "VPN-сеанс изменился. Откройте проверку заново.";
        }
        catch (NetworkInformationException)
        {
            if (!IsDisposed) result.Text = "Windows не вернула параметры сети. Повторите проверку.";
        }
        finally
        {
            running = null;
            if (!IsDisposed) check.Enabled = destination.Enabled = mode.Enabled = port.Enabled = true;
        }
    }
}
