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
 public string[] DnsDomains { get; set; } = [];
 public string[] Hosts { get; set; } = [];
 public string[] OptionalHosts { get; set; } = [];
 public void Validate()
 {
  if (!Uri.TryCreate(Server, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" || uri.Port is < 1 or > 65535)
   throw new ArgumentException("Сервер: нужен HTTPS-адрес без пароля, параметров и фрагмента.");
  Host(uri.Host);
  if (User.Length > 256 || User.Any(char.IsControl)) throw new ArgumentException("Проверьте логин.");
  if (AutoRdp || Rdp.Length > 0) LocalFile(Rdp, ".rdp");
  if (AutoTrueConf || TrueConf.Length > 0) { LocalFile(TrueConf, ".exe"); Host(TrueConfHost); if (TrueConfFallback.Length > 0) IPv4(TrueConfFallback); }
  if (TrueConfPort is < 1 or > 65535) throw new ArgumentException("Неверный порт.");
  if (ExtraHosts.Length > 32 || Hosts.Length + OptionalHosts.Length > 40) throw new ArgumentException("Слишком много рабочих адресов.");
  foreach (string host in ExtraHosts.Concat(Hosts).Concat(OptionalHosts)) Host(host);
  if(DnsDomains.Length>8)throw new ArgumentException("Слишком много рабочих DNS-доменов.");
  foreach(string domain in DnsDomains){Host(domain);if(IPAddress.TryParse(domain,out _))throw new ArgumentException("Нужен DNS-домен, не IP-адрес.");}
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
  // RDP belongs to mstsc: no target validation, allowlist, DNS or TCP acceptance.
  // Recognizable IPv4/DNS endpoints are only best-effort route hints. Short names,
  // system gateway profiles and other RDP syntax remain untouched for Windows.
  var hints=new List<string>();
  void Hint(string value){
   var parts=value.Split(':');if(parts.Length>2)return;
   string name=parts[0].Trim();try{Host(name);}catch(ArgumentException){return;}
   hints.Add(name);
  }
  Hint(Get("full address"));
  if(Get("gatewayusagemethod") is not ("0" or "4"))Hint(Get("gatewayhostname"));
  Hosts=ExtraHosts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
  OptionalHosts=hints.Concat(TrueConf.Length>0?new[]{TrueConfHost,TrueConfFallback}.Where(x=>x.Length>0):[])
   .Except(Hosts,StringComparer.OrdinalIgnoreCase).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
  Validate();
 }
 public static readonly JsonSerializerOptions Json = new() { WriteIndented = true, MaxDepth = 16 };
}

public sealed record Status(string Stage, string Message, bool Ready = false, bool Restored = false);

public static class LaunchGate
{
 public static bool CanLaunch(Status state, bool workerAlive) => workerAlive && state.Stage == "connected" && state.Ready;
}
