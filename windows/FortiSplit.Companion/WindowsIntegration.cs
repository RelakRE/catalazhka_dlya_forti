using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace FortiSplit.Companion;

public sealed record AdapterChoice(string Id, string Name)
{
    public override string ToString() => Name;
}

public static class WindowsIntegration
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestInterface(uint destination, out uint index);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(IntPtr window, int command);

    public static bool IsFortinet(NetworkInterface adapter) =>
        (adapter.Description + " " + adapter.Name).Contains("Fortinet", StringComparison.OrdinalIgnoreCase)
        || (adapter.Description + " " + adapter.Name).Contains("FortiClient", StringComparison.OrdinalIgnoreCase);

    public static AdapterChoice[] Adapters() => NetworkInterface.GetAllNetworkInterfaces().Where(IsFortinet)
        .Select(adapter => new AdapterChoice(adapter.Id, $"{adapter.Name} — {adapter.Description}")).ToArray();

    public static bool HasVpnRoute(WorkplaceSettings settings)
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(x => x.Id == settings.AdapterId);
        if (adapter is null) return false;
        bool fortinet = IsFortinet(adapter), up = adapter.OperationalStatus == OperationalStatus.Up;
        bool ipv4 = adapter.GetIPProperties().UnicastAddresses.Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork
            && !IPAddress.IsLoopback(x.Address) && x.Address.GetAddressBytes()[0] != 169);
        if (!fortinet || !up || !ipv4) return WorkplaceRun.Eligible(up, fortinet, ipv4, false, true);
        var bytes = IPAddress.Parse(settings.ProbeAddress).GetAddressBytes();
        var index = adapter.GetIPProperties().GetIPv4Properties()?.Index;
        bool routed = index.HasValue && GetBestInterface(BitConverter.ToUInt32(bytes), out var best) == 0
            && best == (uint)index.Value;
        return WorkplaceRun.Eligible(up, fortinet, ipv4, routed, true);
    }

    public static async Task<bool> ConfirmEndpoint(WorkplaceSettings settings, CancellationToken cancellation)
    {
        if (!HasVpnRoute(settings)) return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        using var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            await client.ConnectAsync(IPAddress.Parse(settings.ProbeAddress), settings.ProbePort, deadline.Token);
            return HasVpnRoute(settings) && client.Connected;
        }
        catch (SocketException) { return false; }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { return false; }
    }

    public static string FindForti()
    {
        foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var path = Path.Combine(root, "Fortinet", "FortiClient", "FortiClient.exe");
            if (File.Exists(path)) return path;
        }
        return "";
    }

    public static void OpenExecutable(string path)
    {
        WorkplaceSettings.ValidatePath(path, ".exe"); SettingsStore.RegularFile(path);
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = false });
    }

    public static void OpenRdp(string file)
    {
        WorkplaceSettings.ValidatePath(file, ".rdp"); SettingsStore.RegularFile(file);
        var mstsc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstsc.exe");
        var process = new ProcessStartInfo(mstsc) { UseShellExecute = false };
        process.ArgumentList.Add(file);
        Process.Start(process);
    }

    public static void MinimizeForti(string path)
    {
        using var current = Process.GetCurrentProcess();
        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path)))
        {
            using (process)
            {
                try
                {
                    if (process.SessionId == current.SessionId
                        && string.Equals(process.MainModule?.FileName, path, StringComparison.OrdinalIgnoreCase)
                        && process.MainWindowHandle != IntPtr.Zero)
                        ShowWindowAsync(process.MainWindowHandle, 6); // Minimize, never close/kill VPN.
                }
                catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
                { /* A managed client may disallow inspecting its process. VPN remains untouched. */ }
            }
        }
    }

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunName = "FortiSplitCompanion";
    public static bool LoginEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return string.Equals(key?.GetValue(RunName) as string, LoginCommand(), StringComparison.Ordinal);
    }
    private static string LoginCommand()
    {
        var command = "\"" + (Environment.ProcessPath ?? throw new IOException("Неизвестный путь приложения.")) + "\" --login";
        if (command.Length > 260) throw new IOException("Для автозапуска перенесите приложение в папку с более коротким путём.");
        return command;
    }
    public static void SetLogin(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, true);
        if (enabled) key.SetValue(RunName, LoginCommand(), RegistryValueKind.String);
        else key.DeleteValue(RunName, false);
    }
}
