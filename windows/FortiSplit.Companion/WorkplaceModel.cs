using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FortiSplit.Companion;

public sealed record WorkplaceSettings
{
    public int Schema { get; set; } = 1;
    public bool SetupComplete { get; set; }
    public string FortiPath { get; set; } = "";
    public string AdapterId { get; set; } = "";
    public string ProbeAddress { get; set; } = "";
    public int ProbePort { get; set; } = 3389;
    public bool LaunchRdp { get; set; }
    public string RdpPath { get; set; } = "";
    public bool LaunchTrueConf { get; set; }
    public string TrueConfPath { get; set; } = "";
    public bool MinimizeForti { get; set; } = true;

    public static void ValidatePath(string? path, string extension, bool required = true)
    {
        if (!required && path == "") return;
        if (string.IsNullOrWhiteSpace(path) || path.Length > 8192 || !Path.IsPathFullyQualified(path)
            || path.StartsWith(@"\\", StringComparison.Ordinal) || path.Any(char.IsControl)
            || !Path.GetExtension(path).Equals(extension, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Выберите локальный файл {extension}; URL и команды не поддерживаются.");
    }

    public void Validate()
    {
        if (Schema != 1) throw new ArgumentException("Неизвестная версия настроек.");
        ValidatePath(FortiPath, ".exe");
        if (string.IsNullOrWhiteSpace(AdapterId) || AdapterId.Length > 256)
            throw new ArgumentException("Выберите сетевой адаптер Fortinet.");
        if (!IPAddress.TryParse(ProbeAddress, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork
            || IPAddress.IsLoopback(ip) || ip.GetAddressBytes()[0] is 0 or >= 224
            || (ip.GetAddressBytes()[0] == 169 && ip.GetAddressBytes()[1] == 254))
            throw new ArgumentException("Укажите контрольный рабочий IPv4, доступный через VPN.");
        if (ProbePort is < 1 or > 65535) throw new ArgumentException("TCP-порт должен быть от 1 до 65535.");
        ValidatePath(RdpPath, ".rdp", LaunchRdp);
        ValidatePath(TrueConfPath, ".exe", LaunchTrueConf);
    }
}

public sealed class SettingsStore(string directory)
{
    public string DirectoryPath { get; } = Path.GetFullPath(directory);
    public string FilePath => Path.Combine(DirectoryPath, "settings.json");
    private static readonly JsonSerializerOptions JsonOptions = new()
    { WriteIndented = true, MaxDepth = 16, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

    public static void RegularFile(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new IOException("Выберите обычный локальный файл, не ссылку.");
    }

    private void SecureDirectory()
    {
        Directory.CreateDirectory(DirectoryPath);
        if ((File.GetAttributes(DirectoryPath) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Каталог настроек не должен быть ссылкой.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var user = WindowsIdentity.GetCurrent().User ?? throw new IOException("Не удалось определить пользователя.");
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, inherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(security);
    }

    public WorkplaceSettings? Load()
    {
        if (!File.Exists(FilePath)) return null;
        if ((File.GetAttributes(DirectoryPath) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Каталог настроек не должен быть ссылкой.");
        RegularFile(FilePath);
        using var stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var data = new byte[65537];
        int count = 0, read;
        while (count < data.Length && (read = stream.Read(data, count, data.Length - count)) > 0) count += read;
        if (count > 65536) throw new IOException("Настройки превышают 64 KiB.");
        using var document = JsonDocument.Parse(data.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 16 });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new IOException("Ожидается JSON-объект.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in document.RootElement.EnumerateObject())
            if (!names.Add(field.Name)) throw new IOException("Повторяющееся поле настроек.");
        var value = JsonSerializer.Deserialize<WorkplaceSettings>(data.AsSpan(0, count), JsonOptions)
            ?? throw new IOException("Пустые настройки.");
        value.Validate();
        return value;
    }

    public void Save(WorkplaceSettings value)
    {
        value.Validate();
        SecureDirectory();
        var temporary = Path.Combine(DirectoryPath, ".settings-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            { stream.Write(JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions)); stream.Flush(true); }
            File.Move(temporary, FilePath, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}

public enum RunPhase { Idle, Waiting, Ready }

public sealed class WorkplaceRun
{
    public Guid Id { get; private set; }
    public RunPhase Phase { get; private set; }
    private DateTimeOffset started;
    public Guid Begin(DateTimeOffset now)
    {
        if (Phase != RunPhase.Idle) return Id;
        Id = Guid.NewGuid(); started = now; Phase = RunPhase.Waiting; return Id;
    }
    public void Cancel() { Id = Guid.NewGuid(); Phase = RunPhase.Idle; }
    public bool Confirm(Guid id)
    {
        if (id != Id || Phase != RunPhase.Waiting) return false;
        Phase = RunPhase.Ready; return true;
    }
    public bool Expire(DateTimeOffset now)
    {
        if (Phase != RunPhase.Waiting || now - started <= TimeSpan.FromMinutes(5)) return false;
        Cancel(); return true;
    }
    public static bool Eligible(bool up, bool fortinet, bool ipv4, bool route, bool tcp) => up && fortinet && ipv4 && route && tcp;
}
