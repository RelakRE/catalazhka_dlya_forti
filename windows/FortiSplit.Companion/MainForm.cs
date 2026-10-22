using System.Drawing.Drawing2D;
using Microsoft.Win32;

namespace FortiSplit.Companion;

public sealed class MainForm : Form
{
    private readonly SettingsStore store;
    private readonly bool testMode;
    private WorkplaceSettings settings;
    private readonly WorkplaceRun run = new();
    private CancellationTokenSource? cancellation;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 4000 };
    private bool checking, exiting, readyWasLost;
    private int wizardStep;
    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly Label title = Label("Готово к началу работы", 21);
    private readonly Label detail = Label("", 12);
    private readonly Label error = Label("", 11);
    private readonly Button primary = Button("Начать работу");
    private readonly FlowLayoutPanel wizard = Column();
    private readonly FlowLayoutPanel configuration = Column();
    private readonly TextBox forti = Input(), probe = Input(), rdp = Input(), trueConf = Input();
    private readonly ComboBox adapter = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 560 };
    private readonly NumericUpDown port = new() { Minimum = 1, Maximum = 65535, Value = 3389, Width = 130 };
    private readonly CheckBox rdpAuto = Check("Открывать выбранный RDP после подтверждения VPN");
    private readonly CheckBox trueAuto = Check("Запускать TrueConf после подтверждения VPN");
    private readonly CheckBox minimize = Check("Сворачивать FortiClient после подтверждения VPN");
    private readonly CheckBox login = Check("Открывать Companion при входе в Windows (без подключения VPN)");
    private readonly NotifyIcon tray;
    private readonly List<Icon> icons = [];
    private readonly ToolStripMenuItem trayAction = new("Начать работу");

    private static Label Label(string text, float size) => new()
    { Text = text, AutoSize = true, MaximumSize = new Size(590, 0), Font = new Font("Segoe UI", size), Margin = new Padding(0, 0, 0, 16) };
    private static Button Button(string text) => new()
    { Text = text, AutoSize = false, Width = 570, Height = 44, Margin = new Padding(0, 4, 0, 12), FlatStyle = FlatStyle.Flat };
    private static TextBox Input() => new() { Width = 560, Margin = new Padding(0, 0, 0, 10) };
    private static CheckBox Check(string text) => new() { Text = text, AutoSize = true, MaximumSize = new Size(580, 0), Margin = new Padding(0, 8, 0, 10) };
    private static FlowLayoutPanel Column() => new()
    { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Width = 590 };

    public MainForm(SettingsStore store, bool testMode = false, WorkplaceSettings? initial = null)
    {
        this.store = store; this.testMode = testMode;
        settings = initial ?? new WorkplaceSettings { FortiPath = WindowsIntegration.FindForti() };
        if (!testMode)
        {
            try { settings = store.Load() ?? settings; }
            catch (Exception ex) { error.Text = "Настройки не прочитаны: " + ex.Message; }
        }
        Text = "Forti Split — Windows Companion Preview";
        ClientSize = new Size(690, 650); MinimumSize = new Size(650, 600);
        AutoScaleMode = AutoScaleMode.Dpi; Font = new Font("Segoe UI", 11);
        var work = new TabPage("Работа") { AutoScroll = true, Padding = new Padding(24) };
        var options = new TabPage("Настройки") { AutoScroll = true, Padding = new Padding(24) };
        tabs.TabPages.Add(work); tabs.TabPages.Add(options); Controls.Add(tabs);
        var main = Column(); main.Controls.AddRange([Label("Windows Companion · 0.1 Preview", 13), title, detail, error, wizard, primary,
            Label("Эта Windows-версия НЕ меняет маршруты и НЕ восстанавливает интернет при полном VPN. Проверяется только рабочее подключение. Пароли и MFA вводятся в FortiClient и RDP-клиенте.", 11)]);
        work.Controls.Add(main);
        BuildConfiguration(); options.Controls.Add(configuration);
        primary.Click += (_, _) => PrimaryAction();
        forti.Text = settings.FortiPath; probe.Text = settings.ProbeAddress; port.Value = settings.ProbePort;
        rdp.Text = settings.RdpPath; trueConf.Text = settings.TrueConfPath;
        rdpAuto.Checked = settings.LaunchRdp; trueAuto.Checked = settings.LaunchTrueConf;
        minimize.Checked = settings.MinimizeForti;
        if (!testMode)
        {
            try { RefreshAdapters(); } catch (Exception ex) { error.Text = "Не удалось получить адаптеры: " + ex.Message; }
            try { login.Checked = WindowsIntegration.LoginEnabled(); } catch (Exception ex) { error.Text = "Не удалось прочитать настройку автозапуска: " + ex.Message; }
        }
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => ShowWork());
        trayAction.Click += (_, _) => PrimaryAction(); menu.Items.Add(trayAction);
        menu.Items.Add("Настройки", null, (_, _) => { ShowWork(); tabs.SelectedIndex = 1; });
        menu.Items.Add("Выход (VPN остаётся под управлением FortiClient)", null, (_, _) => { exiting = true; Close(); });
        foreach (var color in new[] { Color.SlateGray, Color.DarkOrange, Color.SeaGreen, Color.Firebrick }) icons.Add(CreateIcon(color));
        Icon = icons[0];
        tray = new NotifyIcon { Text = "Forti Split Companion", Icon = icons[0], ContextMenuStrip = menu, Visible = !testMode };
        tray.DoubleClick += (_, _) => ShowWork();
        timer.Tick += async (_, _) => await Poll();
        if (!testMode) { timer.Start(); SystemEvents.UserPreferenceChanged += ThemeChanged; }
        ApplyTheme(); UpdateView();
        FormClosing += (_, args) =>
        {
            if (!exiting && args.CloseReason == CloseReason.UserClosing && !testMode) { args.Cancel = true; Hide(); }
            else { run.Cancel(); cancellation?.Cancel(); }
        };
    }

    private void BuildConfiguration()
    {
        var chooseForti = Button("Выбрать FortiClient.exe…"); chooseForti.Click += (_, _) => Choose(forti, "Приложение|*.exe");
        var refresh = Button("Обновить список адаптеров"); refresh.Click += (_, _) =>
        { try { RefreshAdapters(); } catch (Exception ex) { error.Text = "Не удалось получить адаптеры: " + ex.Message; tabs.SelectedIndex = 0; UpdateView(); } };
        var chooseRdp = Button("Выбрать доверенный .rdp-файл…"); chooseRdp.Click += (_, _) => Choose(rdp, "Подключение RDP|*.rdp");
        var chooseTrue = Button("Выбрать TrueConf.exe…"); chooseTrue.Click += (_, _) => Choose(trueConf, "Приложение|*.exe");
        var save = Button("Сохранить настройки"); save.Click += (_, _) => SaveConfiguration();
        configuration.Controls.AddRange([Label("Настройки рабочего места", 20),
            Label("Клиенты устанавливаются отдельно. Выбирайте только доверенные локальные приложения и RDP-файлы. Не добавляйте пароли в эти настройки.", 11),
            Label("FortiClient", 13), forti, chooseForti, Label("Адаптер Fortinet", 13), adapter, refresh,
            Label("Контрольный IPv4 рабочего сервера и TCP-порт", 13), probe, port,
            Label("Например, адрес вашего RDP и его порт. Запуск разрешён только когда маршрут к нему проходит через выбранный адаптер и TCP-подключение успешно. Если адаптер не определяется, автоматический запуск недоступен.", 11),
            rdpAuto, rdp, chooseRdp, trueAuto, trueConf, chooseTrue, minimize, login, save,
            Label("Companion не закрывает RDP/звонки, не отключает VPN автоматически и не меняет FortiGate/EMS, DNS, маршруты или защитные политики.", 11)]);
    }

    private void RefreshAdapters()
    {
        var selected = (adapter.SelectedItem as AdapterChoice)?.Id ?? settings.AdapterId;
        adapter.Items.Clear();
        adapter.Items.AddRange(WindowsIntegration.Adapters().Cast<object>().ToArray());
        for (int i = 0; i < adapter.Items.Count; i++)
            if (adapter.Items[i] is AdapterChoice choice && choice.Id == selected) adapter.SelectedIndex = i;
        if (adapter.SelectedIndex < 0 && adapter.Items.Count == 1) adapter.SelectedIndex = 0;
    }
    private static void Choose(TextBox destination, string filter)
    {
        using var dialog = new OpenFileDialog { Filter = filter, CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog() == DialogResult.OK) destination.Text = dialog.FileName;
    }

    private WorkplaceSettings ReadConfiguration() => new()
    {
        SetupComplete = true, FortiPath = forti.Text.Trim(), AdapterId = (adapter.SelectedItem as AdapterChoice)?.Id ?? "",
        ProbeAddress = probe.Text.Trim(), ProbePort = (int)port.Value,
        LaunchRdp = rdpAuto.Checked, RdpPath = rdp.Text.Trim(), LaunchTrueConf = trueAuto.Checked,
        TrueConfPath = trueConf.Text.Trim(), MinimizeForti = minimize.Checked
    };
    private bool SaveConfiguration()
    {
        if (run.Phase != RunPhase.Idle) return false;
        try
        {
            var proposed = ReadConfiguration(); proposed.Validate();
            SettingsStore.RegularFile(proposed.FortiPath);
            if (proposed.LaunchRdp) SettingsStore.RegularFile(proposed.RdpPath);
            if (proposed.LaunchTrueConf) SettingsStore.RegularFile(proposed.TrueConfPath);
            if (testMode) throw new InvalidOperationException("Self-test cannot register startup or save real settings.");
            store.Save(proposed); settings = proposed;
            WindowsIntegration.SetLogin(login.Checked); // Explicit user Save, never startup/timer.
            error.Text = ""; tabs.SelectedIndex = 0;
            UpdateView(); return true;
        }
        catch (Exception ex) { error.Text = ex.Message; tabs.SelectedIndex = 0; UpdateView(); return false; }
    }

    private void PrimaryAction()
    {
        if (!settings.SetupComplete) { WizardAction(); return; }
        if (run.Phase != RunPhase.Idle)
        {
            bool wasReady = run.Phase == RunPhase.Ready;
            run.Cancel(); cancellation?.Cancel();
            detail.Text = wasReady ? "Рабочие приложения не закрывались. Отключите VPN в FortiClient, когда закончите работу." : "Запуск отменён. VPN и открытые приложения не изменялись.";
            if (wasReady && !testMode) { try { WindowsIntegration.OpenExecutable(settings.FortiPath); } catch (Exception ex) { error.Text = ex.Message; } }
            UpdateView(); return;
        }
        try
        {
            settings.Validate();
            if (testMode) throw new InvalidOperationException("Self-test cannot open applications.");
            error.Text = ""; readyWasLost = false;
            cancellation?.Dispose(); cancellation = new CancellationTokenSource();
            run.Begin(DateTimeOffset.UtcNow);
            WindowsIntegration.OpenExecutable(settings.FortiPath);
        }
        catch (Exception ex) { run.Cancel(); error.Text = ex.Message; }
        UpdateView();
    }

    private void WizardAction()
    {
        try
        {
            if (wizardStep == 0)
            {
                if (string.IsNullOrEmpty(forti.Text)) { Choose(forti, "FortiClient|*.exe"); return; }
                WorkplaceSettings.ValidatePath(forti.Text, ".exe"); SettingsStore.RegularFile(forti.Text);
                wizardStep++;
            }
            else if (wizardStep == 1)
            {
                var value = ReadConfiguration() with { LaunchRdp = false, RdpPath = "", LaunchTrueConf = false, TrueConfPath = "" };
                value.Validate(); wizardStep++;
            }
            else
            {
                if (rdpAuto.Checked && string.IsNullOrEmpty(rdp.Text)) { Choose(rdp, "Подключение RDP|*.rdp"); return; }
                if (trueAuto.Checked && string.IsNullOrEmpty(trueConf.Text)) { Choose(trueConf, "TrueConf|*.exe"); return; }
                if (!SaveConfiguration()) return;
            }
            error.Text = "";
        }
        catch (Exception ex) { error.Text = ex.Message; }
        UpdateView();
    }

    private async Task Poll()
    {
        if (checking || run.Phase == RunPhase.Idle || testMode) return;
        if (run.Expire(DateTimeOffset.UtcNow)) { cancellation?.Cancel(); error.Text = "Ожидание VPN истекло. Повторный запуск выполняется только кнопкой."; UpdateView(); return; }
        var id = run.Id; var snapshot = settings with { };
        checking = true;
        try
        {
            if (run.Phase == RunPhase.Ready)
            {
                if (!WindowsIntegration.HasVpnRoute(snapshot))
                { run.Cancel(); readyWasLost = true; error.Text = "VPN или маршрут изменился. Автоматического переподключения нет; проверьте FortiClient."; }
            }
            else if (await WindowsIntegration.ConfirmEndpoint(snapshot, cancellation?.Token ?? CancellationToken.None)
                     && run.Confirm(id))
            {
                var failures = new List<string>();
                if (snapshot.MinimizeForti) { try { WindowsIntegration.MinimizeForti(snapshot.FortiPath); } catch { failures.Add("FortiClient не удалось свернуть; VPN не отключался."); } }
                if (snapshot.LaunchTrueConf) { try { WindowsIntegration.OpenExecutable(snapshot.TrueConfPath); } catch (Exception ex) { failures.Add("TrueConf: " + ex.Message); } }
                if (snapshot.LaunchRdp) { try { WindowsIntegration.OpenRdp(snapshot.RdpPath); } catch (Exception ex) { failures.Add("RDP: " + ex.Message); } }
                error.Text = string.Join(Environment.NewLine, failures);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (id == run.Id) { run.Cancel(); error.Text = "Проверка не завершилась: " + ex.Message; } }
        finally { checking = false; if (!IsDisposed) UpdateView(); }
    }

    private void UpdateView()
    {
        configuration.Enabled = run.Phase == RunPhase.Idle;
        wizard.Visible = !settings.SetupComplete;
        if (!settings.SetupComplete)
        {
            // Move the same controls between the wizard and settings; never duplicate state.
            wizard.Controls.Clear();
            if (wizardStep == 0) { title.Text = "Шаг 1 из 3 · FortiClient"; detail.Text = "Укажите установленный официальный FortiClient. Пароли и MFA будут вводиться только в нём."; wizard.Controls.Add(forti); primary.Text = string.IsNullOrEmpty(forti.Text) ? "Выбрать FortiClient.exe…" : "Продолжить"; }
            else if (wizardStep == 1)
            {
                title.Text = "Шаг 2 из 3 · Проверка VPN"; detail.Text = "Выберите адаптер Fortinet и рабочий IPv4/TCP-порт, доступный через VPN. Companion не меняет маршруты.";
                wizard.Controls.AddRange([adapter, probe, port]); primary.Text = "Продолжить";
            }
            else
            {
                title.Text = "Шаг 3 из 3 · Рабочие приложения"; detail.Text = "Автозапуски отключены по умолчанию. При выборе опции следующая кнопка попросит файл; позже всё можно изменить в настройках.";
                wizard.Controls.AddRange([rdpAuto, trueAuto, minimize, login]); primary.Text = "Выбрать файлы и завершить настройку";
            }
        }
        else
        {
            if (SharedControls().Any(control => !configuration.Controls.Contains(control))) RestoreConfiguration();
            title.Text = run.Phase == RunPhase.Ready ? "Рабочий VPN подтверждён" : run.Phase == RunPhase.Waiting ? "Ожидаем вход в FortiClient" : "Готово к началу работы";
            primary.Text = run.Phase == RunPhase.Ready ? "Завершить работу" : run.Phase == RunPhase.Waiting ? "Отменить запуск" : "Начать работу";
            if (run.Phase == RunPhase.Waiting) detail.Text = "Завершите вход с кодом iPhone в FortiClient. Проверим маршрут через выбранный адаптер и доступность рабочего TCP-порта, затем один раз откроем выбранные программы.";
            else if (run.Phase == RunPhase.Ready) detail.Text = "Выбранные программы получили команду запуска. Это не подтверждает вход в RDP или качество звонка. Интернет зависит от VPN-политики; разделения маршрутов в этой версии нет.";
            else if (!readyWasLost && string.IsNullOrEmpty(detail.Text)) detail.Text = "Нажмите «Начать работу», затем войдите в FortiClient. Окно можно закрыть — Companion останется в трее.";
        }
        error.ForeColor = Color.Firebrick; error.Visible = error.Text.Length > 0;
        trayAction.Text = primary.Text;
        tray.Icon = icons[error.Text.Length > 0 ? 3 : run.Phase == RunPhase.Ready ? 2 : run.Phase == RunPhase.Waiting ? 1 : 0];
        tray.Text = ("Forti Split: " + title.Text)[..Math.Min(63, ("Forti Split: " + title.Text).Length)];
    }

    private void RestoreConfiguration()
    {
        var retained = SharedControls().ToHashSet();
        foreach (Control control in configuration.Controls.Cast<Control>().ToArray())
        { configuration.Controls.Remove(control); if (!retained.Contains(control)) control.Dispose(); }
        BuildConfiguration();
    }
    private Control[] SharedControls() => [forti, adapter, probe, port, rdpAuto, rdp, trueAuto, trueConf, minimize, login];
    private void ShowWork() { Show(); WindowState = FormWindowState.Normal; tabs.SelectedIndex = 0; Activate(); }
    private void ThemeChanged(object? sender, UserPreferenceChangedEventArgs e)
    { if (!IsDisposed && IsHandleCreated) BeginInvoke((Action)ApplyTheme); }
    private void ApplyTheme()
    {
        bool dark = !SystemInformation.HighContrast && Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is int value && value == 0;
        var background = SystemInformation.HighContrast ? SystemColors.Window : dark ? Color.FromArgb(32, 34, 38) : Color.WhiteSmoke;
        var foreground = SystemInformation.HighContrast ? SystemColors.WindowText : dark ? Color.WhiteSmoke : Color.FromArgb(25, 28, 32);
        void Apply(Control control) { control.BackColor = background; control.ForeColor = foreground; foreach (Control child in control.Controls) Apply(child); }
        Apply(this);
        primary.BackColor = SystemInformation.HighContrast ? SystemColors.Highlight : Color.FromArgb(12, 95, 170);
        primary.ForeColor = SystemInformation.HighContrast ? SystemColors.HighlightText : Color.White;
    }
    private static Icon CreateIcon(Color color)
    {
        using var bitmap = new Bitmap(32, 32); using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias; graphics.Clear(Color.Transparent);
        using var brush = new SolidBrush(color); graphics.FillEllipse(brush, 1, 1, 30, 30);
        using var pen = new Pen(Color.White, 3) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        graphics.DrawLines(pen, [new Point(8, 16), new Point(16, 16), new Point(24, 8)]);
        graphics.DrawLine(pen, 16, 16, 24, 24);
        var handle = bitmap.GetHicon();
        try { using var icon = Icon.FromHandle(handle); return (Icon)icon.Clone(); }
        finally { NativeIcons.DestroyIcon(handle); }
    }
    public void TestLayout(string screenshot)
    {
        CreateControl(); Show(); tabs.SelectedIndex = 1; PerformLayout();
        using var bitmap = new Bitmap(Width, Height); DrawToBitmap(bitmap, new Rectangle(0, 0, Width, Height));
        bitmap.Save(screenshot, System.Drawing.Imaging.ImageFormat.Png);
        tabs.SelectedIndex = 0; PerformLayout();
        using var work = new Bitmap(Width, Height); DrawToBitmap(work, new Rectangle(0, 0, Width, Height));
        work.Save(Path.Combine(Path.GetDirectoryName(screenshot)!, "Windows-Companion-work.png"), System.Drawing.Imaging.ImageFormat.Png);
        Hide();
    }
    public bool TestHasTabs => tabs.TabCount == 2;
    public bool TestSafeDefaults => !rdpAuto.Checked && !trueAuto.Checked && run.Phase == RunPhase.Idle;
    public bool TestWizard()
    {
        adapter.Items.Add(new AdapterChoice("synthetic-adapter", "Test Fortinet")); adapter.SelectedIndex = 0;
        WizardAction(); WizardAction();
        bool offered = wizardStep == 2 && wizard.Controls.Contains(rdpAuto) && wizard.Controls.Contains(trueAuto);
        settings.SetupComplete = true; UpdateView();
        return offered && SharedControls().All(control => configuration.Controls.Contains(control));
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            exiting = true; cancellation?.Cancel(); cancellation?.Dispose(); timer.Dispose(); tray.Dispose();
            if (!testMode) SystemEvents.UserPreferenceChanged -= ThemeChanged;
            foreach (var icon in icons) icon.Dispose();
        }
        base.Dispose(disposing);
    }
}

internal static class NativeIcons
{
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    internal static extern bool DestroyIcon(IntPtr icon);
}
