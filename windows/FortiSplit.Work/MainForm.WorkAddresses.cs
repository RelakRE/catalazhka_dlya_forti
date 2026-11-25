namespace FortiSplit.Work;

internal sealed partial class MainForm
{
    private readonly TextBox workAddressInput = new() { Name = "work-address-input", MaxLength = 2048, PlaceholderText = "Имя, IPv4 или ссылка" };
    private readonly ListBox workAddresses = new() { Name = "work-addresses", AccessibleName = "Рабочие адреса", Height = 106, IntegralHeight = false, HorizontalScrollbar = true };
    private readonly Label workAddressListHeading = new() { AutoSize = true, ForeColor = WorkMuted, Font = MetricSmallFont, Margin = new Padding(0, 5, 0, 4) };
    private readonly Button addWorkAddress = Btn("Добавить");
    private readonly Button removeWorkAddress = Btn("Удалить из списка");
    private readonly Button checkWorkAddress = Btn("Проверить адрес…");

    private void AddWorkAddressEditor(FlowLayoutPanel parent)
    {
        var entry = new TableLayoutPanel { Height = 38, ColumnCount = 2, RowCount = 1 };
        entry.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        entry.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
        entry.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        workAddressInput.Dock = addWorkAddress.Dock = DockStyle.Fill;
        addWorkAddress.Name = "add-work-address";
        StyleSettingsAction(addWorkAddress);
        addWorkAddress.Margin = new Padding(5, 0, 0, 0);
        entry.Controls.Add(workAddressInput, 0, 0);
        entry.Controls.Add(addWorkAddress, 1, 0);
        HelpField(parent, "sites", workAddressInput, entry);
        options.Remove(workAddressInput); // Work addresses can also be edited during a VPN session.

        parent.Controls.Add(workAddressListHeading);
        workAddresses.Margin = new Padding(0, 0, 0, 5);
        parent.Controls.Add(workAddresses);
        FillWidth(parent, workAddresses);
        removeWorkAddress.Name = "remove-work-address";
        checkWorkAddress.Name = "check-selected-work-address";
        AddSettingsActions(parent, checkWorkAddress, removeWorkAddress);

        addWorkAddress.Click += (_, _) => AddWorkAddress();
        workAddressInput.KeyDown += (_, args) =>
        {
            if (args.KeyCode != Keys.Enter) return;
            args.SuppressKeyPress = true;
            if (addWorkAddress.Enabled) AddWorkAddress();
        };
        workAddressInput.TextChanged += (_, _) => RefreshWorkAddressEditor();
        workAddresses.SelectedIndexChanged += (_, _) => RefreshWorkAddressEditor();
        removeWorkAddress.Click += (_, _) =>
        {
            int selected = workAddresses.SelectedIndex;
            if (selected < 0) return;
            workAddresses.Items.RemoveAt(selected);
            if (workAddresses.Items.Count > 0) workAddresses.SelectedIndex = Math.Min(selected, workAddresses.Items.Count - 1);
            settingsNotice.Text = $"Адрес удалён. Нажмите «{saveSettings.Text}».";
            RefreshWorkAddressEditor();
        };
        checkWorkAddress.Click += (_, _) =>
        {
            if (workAddresses.SelectedItem is string host) Try(() => CheckWorkConnection(host));
        };
        RefreshWorkAddressEditor();
    }

    private void AddWorkAddress()
    {
        try
        {
            string[] parsed = Config.ParseWorkHosts(workAddressInput.Text);
            if (parsed.Length != 1) throw new ArgumentException("Введите один рабочий адрес.");
            string host = parsed[0];
            int existing = workAddresses.FindStringExact(host);
            if (existing >= 0)
            {
                workAddresses.SelectedIndex = existing;
                settingsNotice.Text = "Этот адрес уже есть в списке.";
            }
            else
            {
                if (workAddresses.Items.Count >= Config.MaxExtraHosts) throw new ArgumentException("Слишком много рабочих адресов.");
                workAddresses.SelectedIndex = workAddresses.Items.Add(host);
                settingsNotice.Text = $"Адрес добавлен. Нажмите «{saveSettings.Text}».";
            }
            workAddressInput.Clear();
        }
        catch (ArgumentException error) { settingsNotice.Text = error.Message; }
    }

    private string[] WorkAddresses() => workAddresses.Items.Cast<string>().ToArray();

    private void RefreshWorkAddressEditor()
    {
        bool selected = workAddresses.SelectedIndex >= 0;
        workAddressListHeading.Text = workAddresses.Items.Count == 0 ? "Адресов пока нет" : "Добавленные адреса";
        addWorkAddress.Enabled = workAddressInput.Enabled && !string.IsNullOrWhiteSpace(workAddressInput.Text);
        removeWorkAddress.Enabled = workAddressInput.Enabled && selected;
        checkWorkAddress.Enabled = selected && workRequest is null && !stopRequested &&
            LaunchGate.CanLaunch(status, worker is { HasExited: false });
    }
}
