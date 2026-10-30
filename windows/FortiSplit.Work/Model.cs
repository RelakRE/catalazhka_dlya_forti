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
 public static string[] ParseWorkHosts(string text) => text.Split([',',';','\r','\n','\t',' '],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)
  .Select(value=>{
   if(value.Contains("://",StringComparison.Ordinal)){
    if(!Uri.TryCreate(value,UriKind.Absolute,out var url)||url.Scheme is not ("https" or "http")||url.UserInfo.Length>0)throw new ArgumentException("Рабочий сайт: нужна ссылка HTTP/HTTPS без логина и пароля.");
    value=url.DnsSafeHost;
   }
   Host(value);return value.ToLowerInvariant();
  }).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
 public Config WithWorkAddresses(string[] hosts,string[] domains) {
  var updated=this with {ExtraHosts=hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),Hosts=hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),DnsDomains=domains.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()};
  updated.Validate();return updated;
 }
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
public sealed record WorkAddressRequest(string Id,string[] ExtraHosts,string[] DnsDomains) {
 public Config ApplyTo(Config current){if(!Guid.TryParseExact(Id,"N",out _))throw new ArgumentException("Неверный запрос рабочих адресов.");return current.WithWorkAddresses(ExtraHosts,DnsDomains);}
}
public sealed record WorkAddressResult(string Id,bool Success,string Message);
public sealed record VpnExitError(string Kind,string Message)
{
 // OpenConnect 9.21 main.c maps -EPERM (rejected session cookie) to exit 2.
 public static VpnExitError Describe(int code,bool tunnelEstablished) => code==2
  ? new("session_rejected",tunnelEstablished
   ? "VPN отключён: сервер отклонил текущий сеанс. Вход ранее был выполнен; причина отклонения не указана. Если это повторяется, проверьте вход через FortiClient или обратитесь в ИТ."
   : "Вход выполнен, но VPN-сервер отклонил выданный сеанс при создании туннеля. Для новой попытки нажмите «Подключить». Если это повторяется, проверьте вход через FortiClient или обратитесь в ИТ.")
  : new("client_stopped",tunnelEstablished
   ? "VPN-соединение прервано. Причина остановки клиента не определена. Технические сведения сохранены в vpn-exit.json."
   : "Вход выполнен, но VPN-клиент остановился до готовности туннеля. Причина не определена. Нажмите «Подключить» для нового входа; технические сведения сохранены в vpn-exit.json.");
}
public sealed class WorkDnsRetries
{
 private static readonly int[] Delays=[3,10,30];
 public DateTime NextUtc {get;private set;}=DateTime.MaxValue;
 public int Attempts {get;private set;}
 public void Reset(bool unresolved,DateTime now){Attempts=0;NextUtc=unresolved?now.AddSeconds(Delays[0]):DateTime.MaxValue;}
 public bool TakeDue(DateTime now){if(now<NextUtc)return false;Attempts++;NextUtc=Attempts<Delays.Length?now.AddSeconds(Delays[Attempts]):DateTime.MaxValue;return true;}
 public void Complete(bool unresolved){if(!unresolved)NextUtc=DateTime.MaxValue;}
}

public static class LaunchGate
{
 public static bool CanLaunch(Status state, bool workerAlive) => workerAlive && state.Stage == "connected" && state.Ready;
}
