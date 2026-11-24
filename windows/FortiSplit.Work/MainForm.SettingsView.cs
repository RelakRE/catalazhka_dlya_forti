namespace FortiSplit.Work;

internal sealed partial class MainForm
{
    private readonly Label settingsContext = new()
    {
        Name = "settings-session-notice", Dock = DockStyle.Fill, AutoSize = true, Visible = false,
        Margin = new Padding(20, 0, 20, 6), Padding = new Padding(10, 6, 10, 6),
        AccessibleName = "Доступность настроек во время подключения"
    };
    private RadioButton workAddressSection = null!;
    private static readonly Font SettingsNavigationFont = new("Segoe UI", 10);

    private void BuildSettingsView(TabPage settings)
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, BackColor = WorkBackground };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
        var navigation = new TableLayoutPanel { Name = "settings-navigation", Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 1,
            Padding = new Padding(20, 13, 20, 7), Margin = Padding.Empty };
        navigation.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var viewport = new Panel { Name = "settings-viewport", Dock = DockStyle.Fill, Margin = Padding.Empty };
        var footer = new Panel { Name = "settings-footer", Dock = DockStyle.Fill, BackColor = SystemColors.Window,
            Padding = new Padding(20, 12, 20, 12), Margin = Padding.Empty };
        settingsContext.ForeColor = WorkText;
        settingsContext.BackColor = SystemInformation.HighContrast ? SystemColors.Control : Color.FromArgb(227, 235, 246);
        layout.Controls.Add(navigation, 0, 0);
        layout.Controls.Add(settingsContext, 0, 1);
        layout.Controls.Add(viewport, 0, 2);
        layout.Controls.Add(footer, 0, 3);
        settings.Controls.Add(layout);

        var vpn = AddSection("vpn", "VPN");
        var addresses = AddSection("addresses", "Рабочие адреса");
        var apps = AddSection("apps", "Приложения");
        var maintenance = AddSection("maintenance", "Обслуживание");
        workAddressSection = addresses.Navigation;

        var connection = SettingsCard(vpn.Page, "Подключение к VPN");
        server.Name = "vpn-server";
        server.PlaceholderText = "https://…";
        HelpField(connection, "vpn", server);
        HelpField(connection, "login", user);
        HelpOption(connection, "remember", rememberPassword, showSummary: true);
        HelpOption(connection, "auto-connect", autoConnect);

        var routing = SettingsCard(addresses.Page, "Доступ через VPN");
        AddWorkAddressEditor(routing);
        dnsDomains.PlaceholderText = "Домены через запятую";
        HelpField(routing, "domains", dnsDomains);

        var desktop = SettingsCard(apps.Page, "Удалённый рабочий стол", action: rdpButton);
        HelpField(desktop, "rdp", rdp, FilePicker(rdp, "RDP (*.rdp)|*.rdp", "rdp-picker", "Выбрать файл RDP"));
        HelpOption(desktop, "auto-rdp", autoRdp);

        var trueConf = SettingsCard(apps.Page, "TrueConf", action: tcButton);
        HelpField(trueConf, "tc-program", tc, FilePicker(tc, "Программа (*.exe)|*.exe", "trueconf-picker", "Выбрать программу TrueConf"));
        AddTrueConfEndpoint(trueConf);
        HelpOption(trueConf, "auto-tc", autoTc);

        var network = SettingsCard(maintenance.Page, "Сеть и журнал");
        AddSettingsActions(network, restore, logs);
        var profiles = SettingsCard(maintenance.Page, "Профили", "profiles");
        var import = Btn("Импорт профиля…");
        var export = Btn("Экспорт профиля…");
        AddSettingsActions(profiles, import, export).Name = "profile-actions";
        options.AddRange([import, export]);
        import.Click += (_, _) => Try(() =>
        {
            using var dialog = new OpenFileDialog { Filter = "Профиль (*.json)|*.json" };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            Apply(Storage.Read<Config>(dialog.FileName));
            settingsNotice.Text = "Профиль загружен. Проверьте настройки и сохраните.";
        });
        export.Click += (_, _) => Try(() =>
        {
            Config current = Save();
            using var dialog = new SaveFileDialog { Filter = "Приватный профиль (*.local.json)|*.local.json", FileName = "profile.local.json" };
            if (dialog.ShowDialog() == DialogResult.OK) Storage.Save(dialog.FileName, current);
        });
        AddUpdateSettings(SettingsCard(maintenance.Page, "Обновления"));

        saveSettings.Name = "save-settings";
        saveSettings.BackColor = SystemInformation.HighContrast ? SystemColors.Highlight : WorkAccent;
        saveSettings.ForeColor = SystemColors.HighlightText;
        saveSettings.FlatAppearance.BorderSize = 0;
        saveSettings.Font = new Font(Font, FontStyle.Bold);
        saveSettings.Dock = DockStyle.Right;
        saveSettings.Width = 232;
        saveSettings.Margin = Padding.Empty;
        settingsNotice.ForeColor = WorkMuted;
        settingsNotice.Padding = new Padding(0, 0, 12, 0);
        settingsNotice.TextAlign = ContentAlignment.MiddleLeft;
        footer.Controls.Add(settingsNotice);
        footer.Controls.Add(saveSettings);
        saveSettings.Click += (_, _) => Try(() =>
        {
            if (worker is { HasExited: false }) ApplyWorkAddresses();
            else { Save(); settingsNotice.Text = "Настройки сохранены."; }
        });
        vpn.Navigation.Checked = true;

        (FlowLayoutPanel Page, RadioButton Navigation) AddSection(string name, string caption)
        {
            var page = Column();
            page.Name = "settings-page-" + name;
            page.Padding = new Padding(20, 7, 20, 12);
            page.Visible = false;
            viewport.Controls.Add(page);
            var item = new RadioButton { Name = "settings-nav-" + name, Text = caption, Appearance = Appearance.Button,
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, Margin = new Padding(0, 0, 4, 0),
                FlatStyle = FlatStyle.Flat, Font = SettingsNavigationFont, BackColor = SystemColors.Window, ForeColor = WorkText };
            var selectedColor = SystemInformation.HighContrast ? SystemColors.Highlight : WorkAccent;
            item.FlatAppearance.BorderColor = WorkMuted;
            item.FlatAppearance.CheckedBackColor = selectedColor;
            item.CheckedChanged += (_, _) =>
            {
                item.BackColor = item.Checked ? selectedColor : SystemColors.Window;
                item.FlatAppearance.MouseOverBackColor = item.BackColor;
                item.FlatAppearance.MouseDownBackColor = item.BackColor;
                item.ForeColor = item.Checked ? SystemColors.HighlightText : WorkText;
                page.Visible = item.Checked;
                if (item.Checked) page.BringToFront();
            };
            int column = navigation.Controls.Count;
            if (column == navigation.ColumnCount - 1) item.Margin = Padding.Empty;
            navigation.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            navigation.Controls.Add(item, column, 0);
            return (page, item);
        }
    }

    private void AddTrueConfEndpoint(FlowLayoutPanel card)
    {
        var endpoint = new TableLayoutPanel { Height = 67, ColumnCount = 2, RowCount = 2, Margin = new Padding(0, 0, 0, 6) };
        endpoint.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        endpoint.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 147));
        endpoint.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        endpoint.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        AddField("tc-server", tcHost, 0, new Padding(0, 0, 12, 0));
        AddField("tc-port", tcPort, 1, Padding.Empty);
        card.Controls.Add(endpoint);
        FillWidth(card, endpoint);

        void AddField(string key, Control input, int column, Padding margin)
        {
            var title = SettingsFieldTitle(key, input);
            title.Dock = DockStyle.Fill;
            title.Margin = margin;
            input.Dock = DockStyle.Fill;
            input.Margin = margin;
            endpoint.Controls.Add(title, column, 0);
            endpoint.Controls.Add(input, column, 1);
        }
    }

    private FlowLayoutPanel SettingsCard(FlowLayoutPanel page, string title, string? help = null, Button? action = null)
    {
        var card = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = SystemColors.Window, Padding = new Padding(16, 12, 16, 12),
            Margin = new Padding(0, 0, 0, 12) };
        var heading = new Label { Text = title, ForeColor = WorkText, Font = MetricTotalFont, AutoSize = true, Margin = new Padding(0, 2, 0, 12) };
        var header = action is not null ? AppSettingsHeader(heading, action) : help is null ? heading : HelpRow(heading, help);
        card.Controls.Add(header);
        if (header != heading) FillWidth(card, header);
        page.Controls.Add(card);
        void FitCard()
        {
            int width = Math.Max(120, page.ClientSize.Width - page.Padding.Horizontal);
            if (card.MinimumSize.Width != width) card.MinimumSize = new Size(width, 0);
            if (card.MaximumSize.Width != width) card.MaximumSize = new Size(width, 0);
        }
        page.ClientSizeChanged += (_, _) => FitCard();
        FitCard();
        return card;
    }

    private static TableLayoutPanel AppSettingsHeader(Label heading, Button action)
    {
        var header = new TableLayoutPanel { Height = 38, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 6) };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 152));
        header.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        heading.AutoSize = false;
        heading.Dock = action.Dock = DockStyle.Fill;
        heading.TextAlign = ContentAlignment.MiddleLeft;
        heading.Margin = new Padding(0, 0, 8, 0);
        action.Margin = new Padding(0, 1, 0, 1);
        StyleSettingsAction(action);
        header.Controls.Add(heading, 0, 0);
        header.Controls.Add(action, 1, 0);
        return header;
    }

    private TableLayoutPanel FilePicker(TextBox field, string filter, string name, string label)
    {
        var row = new TableLayoutPanel { Name = name, Height = 34, ColumnCount = 2, RowCount = 1 };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 115));
        row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        field.Dock = DockStyle.Fill;
        field.Margin = new Padding(0, 3, 8, 0);
        var browse = Btn("Выбрать…");
        browse.AccessibleName = label;
        browse.Dock = DockStyle.Fill;
        browse.Margin = Padding.Empty;
        StyleSettingsAction(browse);
        browse.Click += (_, _) => Choose(field, filter);
        options.Add(browse);
        row.Controls.Add(field, 0, 0);
        row.Controls.Add(browse, 1, 0);
        return row;
    }

    private static void StyleSettingsAction(Button button)
    {
        button.BackColor = SystemColors.Window;
        button.ForeColor = WorkAccent;
        button.FlatAppearance.BorderColor = WorkMuted;
    }

    private static TableLayoutPanel AddSettingsActions(FlowLayoutPanel card, Button left, Button right)
    {
        StyleSettingsAction(left);
        StyleSettingsAction(right);
        var row = ButtonPair(left, right);
        row.Height = 44;
        card.Controls.Add(row);
        FillWidth(card, row);
        return row;
    }

    private void RefreshSettingsState(bool active, bool addressesEditable)
    {
        settingsContext.Visible = active;
        settingsContext.Text = LaunchGate.CanLaunch(status, active) && !stopRequested
            ? "VPN подключён. Доступны рабочие адреса и DNS." : "Дождитесь завершения подключения или отключения VPN.";
        saveSettings.Text = active ? "Применить рабочие адреса" : "Сохранить настройки";
        saveSettings.Enabled = addressesEditable;
    }

    internal void ShowWorkSites()
    {
        ShowSettings();
        workAddressSection.Checked = true;
    }
}
