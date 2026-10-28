using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace FortiSplit.Work;

public sealed record Config
{
 public string Server { get; set; } = "";
 public string User { get; set; } = "";
 public bool RememberPassword { get; set; }
 public string Rdp { get; set; } = "";
 public bool AutoRdp { get; set; } = true;
 public string TrueConf { get; set; } = "";
 public string TrueConfHost { get; set; } = "";
 public string TrueConfFallback { get; set; } = "";
 public int TrueConfPort { get; set; } = 4307;
 public bool AutoTrueConf { get; set; } = false;
 public bool ConnectOnOpen { get; set; }
 public string[] ExtraHosts { get; set; } = [];
 public string[] Hosts { get; set; } = [];
 public string[] OptionalHosts { get; set; } = [];
 public string ProbeHost { get; set; } = "";
 public int ProbePort { get; set; } = 443;
 public void Validate()
 {
  if (!Uri.TryCreate(Server, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" || uri.Port is < 1 or > 65535)
   throw new ArgumentException("Сервер: нужен HTTPS-адрес без пароля, параметров и фрагмента.");
  Host(uri.Host);
  if (User.Length > 256 || User.Any(char.IsControl)) throw new ArgumentException("Проверьте логин.");
  if (AutoRdp || Rdp.Length > 0) LocalFile(Rdp, ".rdp");
  if (AutoTrueConf || TrueConf.Length > 0) { LocalFile(TrueConf, ".exe"); Host(TrueConfHost); if (TrueConfFallback.Length > 0) IPv4(TrueConfFallback); }
  if (TrueConfPort is < 1 or > 65535 || ProbePort is < 1 or > 65535) throw new ArgumentException("Неверный порт.");
  if (ExtraHosts.Length > 32 || Hosts.Length + OptionalHosts.Length > 40) throw new ArgumentException("Слишком много рабочих адресов.");
  foreach (string host in ExtraHosts.Concat(Hosts).Concat(OptionalHosts)) Host(host);
 }
 public static void LocalFile(string path, string extension)
 {
  if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\") || path.Any(char.IsControl) || !Path.GetExtension(path).Equals(extension, StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
   throw new ArgumentException("Выберите существующий локальный файл " + extension);
 }
 public static bool IPv4(string value)
 {
  if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != value) throw new ArgumentException("Нужен обычный IPv4-адрес.");
  byte[] b = ip.GetAddressBytes();
  if (b[0] is 0 or 127 or >= 224 || (b[0] == 169 && b[1] == 254)) throw new ArgumentException("Недопустимый рабочий IP.");
  return true;
 }
 public static void Host(string value)
 {
  if (value.Length is < 1 or > 253 || value != value.Trim() || value.Any(char.IsControl)) throw new ArgumentException("Неверное имя сервера.");
  if (IPAddress.TryParse(value, out _)) { IPv4(value); return; }
  var labels = value.Split('.');
  if (labels.Length < 2 || !value.Any(char.IsAsciiLetter) || labels.Any(x => x.Length is < 1 or > 63 || x[0] == '-' || x[^1] == '-' || x.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
   throw new ArgumentException("Нужны DNS-имя или IPv4, без команды, URL и порта.");
 }
 public void PrepareRdp(string contents)
 {
  var fields = contents.Split('\n').Select(x => x.Trim().Split(':', 3)).Where(x => x.Length == 3)
   .GroupBy(x => x[0], StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Last()[2], StringComparer.OrdinalIgnoreCase);
  string Get(string key) => fields.GetValueOrDefault(key, "");
  static (string Host, int Port) Endpoint(string value, int fallback) {
   var parts = value.Split(':'); if (parts.Length > 2) throw new ArgumentException("IPv6 RDP пока не поддержан.");
   Host(parts[0]); int port = parts.Length == 2 ? int.Parse(parts[1]) : fallback;
   if (port is < 1 or > 65535) throw new ArgumentException("Неверный RDP-порт."); return (parts[0],port);
  }
  var address = Endpoint(Get("full address"),3389);
  var hosts = new List<string> { address.Host }; ProbeHost = address.Host; ProbePort = address.Port; OptionalHosts = [];
  string gatewayMode = Get("gatewayusagemethod");
  if (gatewayMode is "1" or "2") {
   if (Get("gatewayprofileusagemethod") == "0") throw new ArgumentException("Нужен RDP с явным профилем шлюза.");
   var gateway = Endpoint(Get("gatewayhostname"),443); hosts.Clear(); hosts.Add(gateway.Host); ProbeHost = gateway.Host; ProbePort = gateway.Port;
   // RD Gateway resolves the destination server itself. Detect mode can also
   // try a direct connection, so retain a target route when VPN DNS knows it.
   if(gatewayMode=="2"&&!address.Host.Equals(gateway.Host,StringComparison.OrdinalIgnoreCase))OptionalHosts=[address.Host];
  }
  else if(gatewayMode is not ("" or "0" or "4"))throw new ArgumentException("Выберите RDP с явным шлюзом или прямым подключением.");
  Hosts = hosts.Concat(ExtraHosts).Concat(TrueConf.Length > 0 ? new[] {TrueConfHost, TrueConfFallback}.Where(x=>x.Length>0) : []).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
  OptionalHosts=OptionalHosts.Except(Hosts,StringComparer.OrdinalIgnoreCase).ToArray();
  Validate();
 }
 public static readonly JsonSerializerOptions Json = new() { WriteIndented = true, MaxDepth = 16 };
}

public sealed record Status(string Stage, string Message, bool Ready = false, bool Restored = false);

public static class LaunchGate
{
 public static bool CanLaunch(Status state, bool workerAlive) => workerAlive && state.Stage == "connected" && state.Ready;
}
