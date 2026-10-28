using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

namespace FortiSplit.Work;

internal static class Worker
{
 [DllImport("kernel32.dll")] private static extern bool AllocConsole();
 [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
 [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window,int command);
 private static async Task Drain(StreamReader reader){try{char[] buffer=new char[2048];while(await reader.ReadAsync(buffer)>0)Array.Clear(buffer);}catch(IOException){}}
 [DllImport("kernel32.dll")] private static extern bool GenerateConsoleCtrlEvent(uint type,uint group);
 [DllImport("kernel32.dll")] private static extern bool SetConsoleCtrlHandler(Handler handler,bool add);
 private delegate bool Handler(uint signal);
 private static volatile bool consoleStop;
 private static readonly Handler handler = signal => { consoleStop=true; return true; };
 internal static string StopName(string id) => @"Local\FortiSplitWork-Stop-"+id;
 private static void State(string folder, string stage,string message,bool ready=false,bool restored=false) => Storage.Save(Path.Combine(folder,"status.json"),new Status(stage,message,ready,restored));
 internal static async Task<int> Script(string folder,string mode)
 {
  var info=new ProcessStartInfo(Storage.PowerShell) { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
  foreach(var arg in new[]{"-NoLogo","-NoProfile","-ExecutionPolicy","Bypass","-File",Path.Combine(AppContext.BaseDirectory,"Network.ps1"),"-Mode",mode,"-Session",folder}) info.ArgumentList.Add(arg);
  using var process=Process.Start(info) ?? throw new IOException("Не запущен сетевой обработчик.");
  var stdout=process.StandardOutput.ReadToEndAsync(); var stderr=process.StandardError.ReadToEndAsync();
  // Do not kill a network mutation mid-operation: parent/worker wait for its completion.
  await process.WaitForExitAsync(); await Task.WhenAll(stdout,stderr);
  return process.ExitCode;
 }
 internal static int Run(string id,int parentId,long parentTicks,bool recovery)
 {
  string folder=Storage.SessionPath(id);
  using var identity=WindowsIdentity.GetCurrent();
  if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
  using var mutex=new Mutex(false,@"Global\FortiSplitWork-Session"); bool locked=false;
  Process? vpn=null; bool cleaned=false; string failure="";
  try {
   try { locked=mutex.WaitOne(0); } catch(AbandonedMutexException) { locked=true; }
   if(!locked) throw new IOException("Другой сеанс VPN ещё выполняется.");
   if(recovery) { cleaned=Script(folder,"Cleanup").GetAwaiter().GetResult()==0; State(folder,cleaned?"disconnected":"error",cleaned?"Сетевые настройки восстановлены.":"Очистка не подтверждена. Смотрите журнал.",restored:cleaned); return cleaned?0:1; }
   using var parent=Process.GetProcessById(parentId);
   if(parent.StartTime.ToUniversalTime().Ticks!=parentTicks || !string.Equals(parent.MainModule?.FileName,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase)) throw new IOException("Главное окно недоступно.");
   using var stop=EventWaitHandle.OpenExisting(StopName(id));
   Config config=Storage.Read<Config>(Path.Combine(folder,"config.json")); config.Validate();
   // MinGW builds may not round-trip a Cyrillic --script path. Stage the hook
   // in this private session, which is ASCII on this machine, before connecting.
   if(folder.Any(c=>c>127)) throw new IOException("Для этой сборки OpenConnect нужен профиль Windows с латинским путём AppData.");
   foreach(string file in new[]{"network-hook.js","Network.ps1"}) {
    string destination=Path.Combine(folder,file);Storage.RegularPath(destination);
    File.Copy(Path.Combine(AppContext.BaseDirectory,file),destination,true);
   }
   State(folder,"preparing","Проверяем готовность сети…");
   if(Script(folder,"Preflight").GetAwaiter().GetResult()!=0) throw new IOException("Отключите FortiClient и другие старые сеансы. Подробности — в журнале.");
   // Refuse a new session until every previous journal has been cleaned.
   if(Directory.EnumerateFiles(Path.Combine(Storage.Root,"sessions"),"network.json",SearchOption.AllDirectories).Any(p=>Path.GetDirectoryName(p)!=folder)) throw new IOException("Есть незавершённый сеанс. Нажмите «Восстановить сеть».");
   if(stop.WaitOne(0) || parent.HasExited) return 0;
   State(folder,"authenticating","Введите данные входа в окне приложения.");
   AuthSession login=AuthPipe.Login(id,parentId,config,()=>stop.WaitOne(0)||parent.HasExited);
   if(stop.WaitOne(0)||parent.HasExited)throw new OperationCanceledException();
   if(!AllocConsole() || !SetConsoleCtrlHandler(handler,true)) throw new IOException("Не удалось подготовить VPN-процесс.");
   ShowWindow(GetConsoleWindow(),0);
   var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"client","openconnect.exe")) { UseShellExecute=false,WorkingDirectory=AppContext.BaseDirectory,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true };
   foreach(var arg in new[]{"--protocol=fortinet","--interface=FortiSplitWork","--disable-ipv6","--no-proxy","--no-dtls","--force-dpd=60","--reconnect-timeout=60","--non-inter","--cookie-on-stdin","--resolve",login.Resolve,"--script",Path.Combine(folder,"network-hook.js")}) info.ArgumentList.Add(arg);
   if(config.User.Length>0) { info.ArgumentList.Add("--user");info.ArgumentList.Add(config.User); }
   info.ArgumentList.Add(login.ConnectUrl);info.Environment["FORTISPLIT_SESSION"]=folder;
   vpn=Process.Start(info) ?? throw new IOException("OpenConnect не запустился.");
   vpn.StandardInput.WriteLine(login.Cookie);vpn.StandardInput.Close();login=new("","","");
   _=Drain(vpn.StandardOutput);_=Drain(vpn.StandardError);
   using(var self=Process.GetCurrentProcess()) {
    var guard=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
    foreach(string arg in new[]{"--watch",id,self.Id.ToString(),self.StartTime.ToUniversalTime().Ticks.ToString(),vpn.Id.ToString(),vpn.StartTime.ToUniversalTime().Ticks.ToString()})guard.ArgumentList.Add(arg);
    using var watcher=Process.Start(guard)??throw new IOException("Не запущен независимый процесс очистки.");
    string ready=Path.Combine(folder,"watcher-ready.json");
    var wait=Stopwatch.StartNew();while(!File.Exists(ready)&&!watcher.HasExited&&wait.Elapsed.TotalSeconds<5)Thread.Sleep(50);
    if(!File.Exists(ready))throw new IOException("Процесс очистки не подтвердил готовность.");
   }
   State(folder,"preparing","Вход выполнен. Создаём рабочий туннель…");
   string generation=""; DateTime refresh=DateTime.MaxValue; DateTime authLimit=DateTime.UtcNow.AddMinutes(10);
   while(!vpn.HasExited && !parent.HasExited && !stop.WaitOne(0) && !consoleStop) {
    string path=Path.Combine(folder,"network.json");
    if(File.Exists(Path.Combine(folder,"network-error.txt"))) throw new IOException("Ошибка настройки рабочего туннеля: "+File.ReadAllText(Path.Combine(folder,"network-error.txt")));
    if(File.Exists(path)) {
     JsonElement network=Storage.Read<JsonElement>(path); string current=network.GetProperty("Generation").GetString()!;
     if(network.GetProperty("Stage").GetString()=="base_ready" || (generation.Length>0 && DateTime.UtcNow>=refresh)) {
      State(folder,"configuring","VPN вошёл. Настраиваем рабочий туннель…");
      if(Script(folder,"Resolve").GetAwaiter().GetResult()!=0) throw new IOException("Не удалось настроить рабочие адреса. Смотрите network-error.txt.");
      if(vpn.HasExited || parent.HasExited || stop.WaitOne(0) || consoleStop) break;
      network=Storage.Read<JsonElement>(path);
      Storage.Save(Path.Combine(folder,"work-check.json"),new {Utc=DateTime.UtcNow,RdpPrecheck="disabled",TrueConfPrecheck="disabled",Meaning="VPN_tunnel_ready_application_connectivity_not_tested"});
      if(vpn.HasExited || parent.HasExited || stop.WaitOne(0) || consoleStop) break;
      generation=current; refresh=DateTime.UtcNow.AddMinutes(2);
      State(folder,"connected","VPN подключён. Можно открыть RDP или TrueConf; обычный интернет остаётся напрямую.",true);
     }
    } else if(generation.Length>0) {
     State(folder,"reconnecting","Туннель временно отключён. OpenConnect пытается восстановить соединение…");
    }
    if(generation.Length==0 && DateTime.UtcNow>authLimit) throw new IOException("Время ожидания входа истекло.");
    Thread.Sleep(500);
   }
   if(vpn.HasExited && !stop.WaitOne(0) && !consoleStop) failure="VPN-клиент завершил соединение, код "+vpn.ExitCode+". Для нового входа нажмите «Подключить».";
  } catch(OperationCanceledException) { failure="Вход отменён."; }
  catch(Exception e) { failure=e.Message; }
  finally {
   if(locked && !recovery) {
    try {
     State(folder,"disconnecting","Отключаем VPN и восстанавливаем настройки…");
     if(vpn is not null && !vpn.HasExited) {
      GenerateConsoleCtrlEvent(0,0);
      if(!vpn.WaitForExit(10000)) { vpn.Kill(); vpn.WaitForExit(); }
     }
     cleaned=Script(folder,"Cleanup").GetAwaiter().GetResult()==0;
     State(folder,cleaned?(failure.Length==0?"disconnected":"error"):"recovery_required",
      cleaned?(failure.Length==0?"VPN отключён. Сетевые настройки восстановлены.":failure+" Сетевые настройки восстановлены."):"Восстановление не подтверждено. Нажмите «Восстановить сеть».",restored:cleaned);
    } catch(Exception e) { try { State(folder,"recovery_required","Ошибка завершения: "+e.Message); } catch(Exception) { } }
   }
   vpn?.Dispose(); if(locked) mutex.ReleaseMutex();
  }
  return cleaned?0:1;
 }
 internal static int Watch(string id,int workerId,long workerTicks,int vpnId,long vpnTicks)
 {
  string folder=Storage.SessionPath(id);
  try {
   using var owner=Process.GetProcessById(workerId);
   if(owner.StartTime.ToUniversalTime().Ticks!=workerTicks || !string.Equals(owner.MainModule?.FileName,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase))return 2;
   using var child=Process.GetProcessById(vpnId);
   if(child.StartTime.ToUniversalTime().Ticks!=vpnTicks || !string.Equals(child.MainModule?.FileName,Path.Combine(AppContext.BaseDirectory,"client","openconnect.exe"),StringComparison.OrdinalIgnoreCase))return 2;
   Storage.Save(Path.Combine(folder,"watcher-ready.json"),new{Ready=true});
   owner.WaitForExit();
   using var mutex=new Mutex(false,@"Global\FortiSplitWork-Session");bool locked=false;
   try {
    try{locked=mutex.WaitOne(30000);}catch(AbandonedMutexException){locked=true;}
    if(!locked)return 1;
    // Exact process handle + creation time; never kill FortiClient or other sessions.
    if(!child.HasExited){child.Kill();child.WaitForExit();}
    if(File.Exists(Path.Combine(folder,"network.json"))) {
     bool cleaned=Script(folder,"Cleanup").GetAwaiter().GetResult()==0;
     State(folder,cleaned?"error":"recovery_required",cleaned?"Окно VPN было закрыто. Независимый процесс восстановил настройки.":"Нужна повторная очистка сети.",restored:cleaned);
    }
   }finally{if(locked)mutex.ReleaseMutex();}
   return 0;
  }catch(Exception){return 1;}
 }
}
