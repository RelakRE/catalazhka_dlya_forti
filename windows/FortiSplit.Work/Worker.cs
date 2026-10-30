using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

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
 private sealed record VpnProcess(int Id,long StartTicks,string Image);
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
 internal static void StopSavedClient(string folder)
 {
  string path=Path.Combine(folder,"vpn-process.json");if(!File.Exists(path))return;
  VpnProcess saved=Storage.Read<VpnProcess>(path);
  if(saved.Id==Environment.ProcessId||!Path.IsPathFullyQualified(saved.Image)||!Path.GetFileName(saved.Image).Equals("openconnect.exe",StringComparison.OrdinalIgnoreCase))throw new IOException("Неверные данные VPN-процесса.");
  Process child;try{child=Process.GetProcessById(saved.Id);}catch(ArgumentException){return;}
  using(child){
   if(child.HasExited||child.StartTime.ToUniversalTime().Ticks!=saved.StartTicks)return;
   if(!string.Equals(child.MainModule?.FileName,saved.Image,StringComparison.OrdinalIgnoreCase))throw new IOException("VPN-процесс не соответствует журналу. Его настройки не изменены.");
   child.Kill();child.WaitForExit();
  }
 }
 internal static int Run(string id,int parentId,long parentTicks,bool recovery)
 {
  string folder=Storage.SessionPath(id);
  using var identity=WindowsIdentity.GetCurrent();
  if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
  using var mutex=new Mutex(false,@"Global\FortiSplitWork-Session"); bool locked=false;
  Process? vpn=null; bool cleaned=false; string failure="";
  try {
   if(recovery){try{using var previousStop=EventWaitHandle.OpenExisting(StopName(id));previousStop.Set();}catch(WaitHandleCannotBeOpenedException){}}
   try { locked=mutex.WaitOne(recovery?30000:0); } catch(AbandonedMutexException) { locked=true; }
   if(!locked) throw new IOException("Другой сеанс VPN ещё выполняется.");
   if(recovery) { StopSavedClient(folder);cleaned=Script(folder,"Cleanup").GetAwaiter().GetResult()==0;if(cleaned)File.Delete(Path.Combine(folder,"vpn-process.json")); State(folder,cleaned?"disconnected":"error",cleaned?"Сетевые настройки восстановлены.":"Очистка не подтверждена. Смотрите журнал.",restored:cleaned); return cleaned?0:1; }
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
   // Refuse a new session until every previous journal has been cleaned.
   if(Directory.EnumerateFiles(Path.Combine(Storage.Root,"sessions"),"*.json",SearchOption.AllDirectories).Any(p=>Path.GetDirectoryName(p)!=folder && Path.GetFileName(p) is "network.json" or "vpn-process.json")) throw new IOException("Есть незавершённый сеанс. Нажмите «Восстановить сеть».");
   if(stop.WaitOne(0) || parent.HasExited) return 0;
   State(folder,"authenticating","Введите данные входа в окне приложения.");
   int authStep=0;
   var authTrace=new List<object>();
   void TraceAuth(string evt){if(authTrace.Count>=160)return;authTrace.Add(new{Event=evt,UpdatedUtc=DateTime.UtcNow});Storage.Save(Path.Combine(folder,"auth-trace.json"),authTrace);}
   AuthSession login=AuthPipe.Login(id,parentId,config,()=>stop.WaitOne(0)||parent.HasExited,phase=>{
    // Fixed phase names only: never log forms, replies, credentials or cookies.
    Storage.Save(Path.Combine(folder,"auth-stage.json"),new{Phase=phase,Step=++authStep,UpdatedUtc=DateTime.UtcNow});
    TraceAuth(phase);
    string message=phase switch{
     "form_requested"=>"Введите данные, запрошенные VPN, в окне приложения.",
     "form_submitted"=>"Ответ формы передан VPN-клиенту. Ожидаем сервер; вход ещё не подтверждён. Может появиться повторный запрос пароля или кода…",
     "cookie_obtained"=>"Сервер VPN подтвердил вход. Подготавливаем туннель…",
     _=>"Ожидаем ответ сервера VPN…"
    };
    State(folder,"authenticating",message);
   },TraceAuth);
   if(stop.WaitOne(0)||parent.HasExited)throw new OperationCanceledException();
   if(!AllocConsole() || !SetConsoleCtrlHandler(handler,true)) throw new IOException("Не удалось подготовить VPN-процесс.");
   ShowWindow(GetConsoleWindow(),0);
   var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"client","openconnect.exe")) { UseShellExecute=false,WorkingDirectory=AppContext.BaseDirectory,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true };
   foreach(var arg in new[]{"--protocol=fortinet","--interface=FortiSplitWork","--disable-ipv6","--no-proxy","--no-dtls","--force-dpd=60","--reconnect-timeout=60","--non-inter","--cookie-on-stdin","--resolve",login.Resolve,"--script",Path.Combine(folder,"network-hook.js")}) info.ArgumentList.Add(arg);
   if(config.User.Length>0) { info.ArgumentList.Add("--user");info.ArgumentList.Add(config.User); }
   info.ArgumentList.Add(login.ConnectUrl);info.Environment["FORTISPLIT_SESSION"]=folder;
   vpn=Process.Start(info) ?? throw new IOException("OpenConnect не запустился.");
   Storage.Save(Path.Combine(folder,"vpn-process.json"),new VpnProcess(vpn.Id,vpn.StartTime.ToUniversalTime().Ticks,info.FileName));
   vpn.StandardInput.WriteLine(login.Cookie);vpn.StandardInput.Close();login=new("","","");
   _=Drain(vpn.StandardOutput);_=Drain(vpn.StandardError);
   State(folder,"preparing","Вход выполнен. Создаём рабочий туннель…");
   string generation="";
   string lastWorkRequest="";
   var dnsRetries=new WorkDnsRetries();
   bool ShowNetworkReady(){
    var currentNetwork=Storage.Read<System.Text.Json.JsonElement>(Path.Combine(folder,"network.json"));
    generation=currentNetwork.GetProperty("Generation").GetString()!;
    int unresolved=currentNetwork.TryGetProperty("Unresolved",out var names)?names.GetArrayLength():0;
    string message="VPN подключён. Рабочие адреса настроены; обычный интернет остаётся напрямую.";
    if(unresolved>0)message+=$" DNS пока не определил имена: {unresolved}. Их можно повторно применить в настройках.";
    State(folder,"connected",message,true);return unresolved>0;
   }
   while(!vpn.HasExited && !stop.WaitOne(0) && !consoleStop) {
    string path=Path.Combine(folder,"network.json");
    if(generation.Length==0&&File.Exists(Path.Combine(folder,"network-error.txt")))throw new IOException("Не удалось применить настройки подключения. Нажмите «Восстановить сеть».");
    if(File.Exists(path)) {
     var network=Storage.Read<System.Text.Json.JsonElement>(path); string current=network.GetProperty("Generation").GetString()!;
     if(current!=generation && network.GetProperty("Stage").GetString()=="base_ready") {
      State(folder,"configuring","VPN вошёл. Настраиваем рабочий туннель…");
      if(Script(folder,"Resolve").GetAwaiter().GetResult()!=0) throw new IOException("Не удалось настроить рабочие адреса. Смотрите network-error.txt.");
      if(vpn.HasExited || stop.WaitOne(0) || consoleStop) break;
      dnsRetries.Reset(ShowNetworkReady(),DateTime.UtcNow);
     }
    }
    if(generation.Length>0&&!vpn.HasExited&&!stop.WaitOne(0)&&!consoleStop){
     string requestPath=Path.Combine(folder,"work-address-request.json");
     if(File.Exists(requestPath)){
      var request=Storage.Read<WorkAddressRequest>(requestPath);
      if(request.Id!=lastWorkRequest){
       Config? updated=null;
       try{updated=request.ApplyTo(config);}catch(ArgumentException e){Storage.Save(Path.Combine(folder,"work-address-result.json"),new WorkAddressResult(request.Id,false,e.Message));}
       lastWorkRequest=request.Id;
       if(updated is not null){
        State(folder,"connected","Обновляем IP рабочих сайтов через DNS VPN…",true);
        Storage.Save(Path.Combine(folder,"config.json"),updated);config=updated;
        if(Script(folder,"Resolve").GetAwaiter().GetResult()!=0)throw new IOException("Не удалось обновить рабочие адреса. Смотрите network-error.txt.");
        if(vpn.HasExited||stop.WaitOne(0)||consoleStop)break;
        dnsRetries.Reset(ShowNetworkReady(),DateTime.UtcNow);
        Storage.Save(Path.Combine(folder,"work-address-result.json"),new WorkAddressResult(request.Id,true,"Рабочие адреса применены."));
       }
      }
     }
     if(dnsRetries.TakeDue(DateTime.UtcNow)){
      if(Script(folder,"Retry").GetAwaiter().GetResult()!=0)throw new IOException("Не удалось повторно определить рабочие адреса. Смотрите network-error.txt.");
      if(vpn.HasExited||stop.WaitOne(0)||consoleStop)break;
      dnsRetries.Complete(ShowNetworkReady());
     }
    }
    Thread.Sleep(500);
   }
   if(vpn.HasExited && !stop.WaitOne(0) && !consoleStop){
    var error=VpnExitError.Describe(vpn.ExitCode,generation.Length>0);failure=error.Message;
    Storage.Save(Path.Combine(folder,"vpn-exit.json"),new{ExitCode=vpn.ExitCode,Phase=generation.Length>0?"tunnel_active":"creating_tunnel",Reason=error.Kind,UpdatedUtc=DateTime.UtcNow});
   }
  } catch(OperationCanceledException) { failure="Вход отменён."; }
  catch(Exception e) { failure=e.Message;if(recovery||!locked)State(folder,"recovery_required",failure); }
  finally {
   if(locked && !recovery) {
    try {
     bool requested=consoleStop;try{using var requestedStop=EventWaitHandle.OpenExisting(StopName(id));requested|=requestedStop.WaitOne(0);}catch(WaitHandleCannotBeOpenedException){}
     if(requested){
      State(folder,"disconnecting","Отключаем VPN и восстанавливаем настройки…");
      if(vpn is not null && !vpn.HasExited){GenerateConsoleCtrlEvent(0,0);if(!vpn.WaitForExit(10000)){vpn.Kill();vpn.WaitForExit();}}
      cleaned=Script(folder,"Cleanup").GetAwaiter().GetResult()==0;
      if(cleaned)File.Delete(Path.Combine(folder,"vpn-process.json"));
      State(folder,cleaned?"disconnected":"recovery_required",cleaned?"VPN отключён. Сетевые настройки восстановлены.":"Нажмите «Восстановить сеть».",restored:cleaned);
     }else{
      bool pending=File.Exists(Path.Combine(folder,"network.json"))||(vpn is not null&&!vpn.HasExited);
      if(!pending)File.Delete(Path.Combine(folder,"vpn-process.json"));
      State(folder,pending?"recovery_required":"error",failure+(pending?" Сначала нажмите «Восстановить сеть» и дождитесь подтверждения очистки. Затем нажмите «Подключить» для нового входа.":""),restored:!pending);
     }
    } catch(Exception e) { try { State(folder,"recovery_required","Ошибка завершения: "+e.Message); } catch(Exception) { } }
   }
   vpn?.Dispose(); if(locked) mutex.ReleaseMutex();
  }
  return cleaned?0:1;
 }
}
