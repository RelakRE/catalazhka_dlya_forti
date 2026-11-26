using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace FortiSplit.Work;

internal static class Worker
{
 private const int NetworkChangeRejected=2;
 private const int NetworkGenerationChanged=3;
 private const int NetworkScriptTimeoutMilliseconds=60_000;
 private static readonly TimeSpan NetworkReadyLimit=TimeSpan.FromSeconds(120);
 internal const int AccountMismatchExitCode=4;
 internal const string AccountMismatchMessage="Сетевой компонент должен работать под той же учётной записью, что и Forti Split. Для подключения или восстановления сети подтвердите UAC под этой учётной записью.";
 private const string SessionMutexName=@"Global\FortiSplitWork-Session";
 [DllImport("kernel32.dll")] private static extern bool AllocConsole();
 [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
 [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window,int command);
 private static async Task Drain(StreamReader reader){try{char[] buffer=new char[2048];while(await reader.ReadAsync(buffer)>0)Array.Clear(buffer);}catch(IOException){}}
 [DllImport("kernel32.dll")] private static extern bool GenerateConsoleCtrlEvent(uint type,uint group);
 [DllImport("kernel32.dll")] private static extern bool SetConsoleCtrlHandler(Handler handler,bool add);
 [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,bool inherit,int pid);
 [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
 private delegate bool Handler(uint signal);
 private static volatile bool consoleStop;
 private sealed record VpnProcess(int Id,long StartTicks,string Image);
 private static readonly Handler handler = signal => { consoleStop=true; return true; };
 internal static string StopName(string id) => @"Local\FortiSplitWork-Stop-"+id;
 private static void State(string folder, string stage,string message,bool ready=false,bool restored=false,TunnelCounters? trafficStart=null,WorkTrafficSnapshot? workTraffic=null) => Storage.Save(Path.Combine(folder,"status.json"),new Status(stage,message,ready,restored,trafficStart,workTraffic));
 private static void TryState(string folder,string stage,string message,bool restored=false,WorkTrafficSnapshot? workTraffic=null)
 {
  try { State(folder,stage,message,restored:restored,workTraffic:workTraffic); }
  catch(Exception error) when(error is IOException or UnauthorizedAccessException) { }
 }
 private static bool NetworkReconnecting(string folder) => File.Exists(Path.Combine(folder,"network-reconnecting"));
 private static bool NetworkHookFailed(string folder) => File.Exists(Path.Combine(folder,"network-hook-error.txt"));
 private static WorkNetwork? ReadNetwork(string folder)
 {
  try { return Storage.Read<WorkNetwork>(Path.Combine(folder,"network.json")); }
  catch(IOException error) when(error is FileNotFoundException or DirectoryNotFoundException) { return null; }
 }
 internal static bool NetworkReady(string folder,Status status)
 {
  if(status.NetworkGeneration is not { } generation||NetworkReconnecting(folder)||NetworkHookFailed(folder))return false;
  try { return ReadNetwork(folder) is {Stage:"ready"} network&&network.Generation==generation; }
  catch(Exception error) when(error is IOException or UnauthorizedAccessException or JsonException) { return false; }
 }
 private static int Script(string folder,string mode,string? generation=null,string? ownerSid=null)
 {
  var info=new ProcessStartInfo(Storage.PowerShell) { UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=NetworkScripts.StateDirectory };
  NetworkScripts.SetSystemEnvironment(info,NetworkScripts.StateDirectory);
  foreach(var arg in new[]{"-NoLogo","-NoProfile","-ExecutionPolicy","Bypass","-File",NetworkScripts.PowerShellScript,"-Mode",mode,"-Session",folder}) info.ArgumentList.Add(arg);
  if(generation is not null){info.ArgumentList.Add("-Generation");info.ArgumentList.Add(generation);}
  if(ownerSid is not null){info.ArgumentList.Add("-OwnerSid");info.ArgumentList.Add(ownerSid);}
  using var process=Process.Start(info) ?? throw new IOException("Не запущен сетевой обработчик.");
  if(!process.WaitForExit(NetworkScriptTimeoutMilliseconds)){
   // Every mutation is journaled; cleanup serializes with the network mutex.
   StopProcess(process,entireTree:true);
   throw new IOException("Сетевой обработчик не завершился за отведённое время.");
  }
  return process.ExitCode;
 }
 private static void StopProcess(Process process,bool entireTree=false)
 {
  try{if(!process.HasExited)process.Kill(entireTree);}
  catch(InvalidOperationException) when(process.HasExited){ }
  if(!process.WaitForExit(5000))throw new IOException("Не удалось остановить сетевой процесс.");
 }
 internal static bool ProcessUsesAccount(int pid,SecurityIdentifier sid)
 {
  const uint queryLimitedInformation=0x1000,tokenQuery=0x0008;
  using var process=OpenProcess(queryLimitedInformation,false,pid);
  if(process.IsInvalid||!OpenProcessToken(process,tokenQuery,out var token))
   throw new Win32Exception(Marshal.GetLastWin32Error());
  using(token)
  using(var identity=new WindowsIdentity(token.DangerousGetHandle()))
   return identity.User is { } parentSid && sid.Equals(parentSid);
 }
 private static Process? OpenParent(int pid,long ticks,SecurityIdentifier sid,bool bootstrap)
 {
  try { if(!ProcessUsesAccount(pid,sid))return null; }
  catch(Win32Exception error) when(error.NativeErrorCode==5) { return null; }
  var parent=Process.GetProcessById(pid);
  try{
   string self=Environment.ProcessPath!, ui=parent.MainModule?.FileName??"";
   bool installed=string.Equals(self,NetworkScripts.WorkerExecutable,StringComparison.OrdinalIgnoreCase);
   if(parent.StartTime.ToUniversalTime().Ticks!=ticks || bootstrap==installed ||
      (bootstrap ? !string.Equals(ui,self,StringComparison.OrdinalIgnoreCase) : !SameExecutable(self,ui)))
    throw new IOException("Главное окно недоступно.");
   return parent;
  }catch{
   parent.Dispose();
   throw;
  }
 }
 private static bool SameExecutable(string worker,string ui)
 {
  if (!Path.IsPathFullyQualified(ui)) return false;
  using var expected=File.OpenRead(worker);
  using var actual=File.OpenRead(ui);
  return expected.Length==actual.Length && SHA256.HashData(expected).SequenceEqual(SHA256.HashData(actual));
 }
 internal static void StopSavedClient(string journalPath)
 {
  if(!File.Exists(journalPath))return;
  VpnProcess saved=Storage.Read<VpnProcess>(journalPath);
  if(saved.Id==Environment.ProcessId||!Path.IsPathFullyQualified(saved.Image)||!Path.GetFileName(saved.Image).Equals("openconnect.exe",StringComparison.OrdinalIgnoreCase))throw new IOException("Неверные данные VPN-процесса.");
  Process child;try{child=Process.GetProcessById(saved.Id);}catch(ArgumentException){return;}
  using(child){
   if(child.HasExited||child.StartTime.ToUniversalTime().Ticks!=saved.StartTicks)return;
   if(!string.Equals(child.MainModule?.FileName,saved.Image,StringComparison.OrdinalIgnoreCase))throw new IOException("VPN-процесс не соответствует журналу. Его настройки не изменены.");
   StopProcess(child);
  }
 }
 internal static int Recover(string requestId,int parentId,long parentTicks,bool bootstrap)
 {
  using var identity=WindowsIdentity.GetCurrent();
  if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))return 2;
  using var parent=OpenParent(parentId,parentTicks,identity.User!,bootstrap);
  if(parent is null)return AccountMismatchExitCode;
  string sid=identity.User!.Value,resultFolder=NetworkScripts.SessionPath(sid,requestId);
  using var mutex=new Mutex(false,SessionMutexName);
  bool locked=false;
  try{
   NetworkScripts.PrepareSession(sid,requestId);
   // A worker still finishing a session can release the mutex after its stop signal.
   foreach(string id in Storage.SessionsWithRecoveryFiles()){
    try{using var previousStop=EventWaitHandle.OpenExisting(StopName(id));previousStop.Set();}
    catch(WaitHandleCannotBeOpenedException){ }
   }
   try{locked=mutex.WaitOne(30000);}catch(AbandonedMutexException){locked=true;}
   if(!locked)throw new IOException("Другой сеанс VPN ещё выполняется.");
   NetworkScripts.Prepare();
   if(bootstrap)NetworkScripts.InstallWorker(Environment.ProcessPath!);
   var sessions=NetworkScripts.PendingSessions(NetworkScripts.StateDirectory).Distinct().ToArray();
   var recovered=new List<RecoveredSession>();
   int failures=0;
   foreach(var (ownerSid,id) in sessions){
    string folder=NetworkScripts.SessionPath(ownerSid,id),journalPath=NetworkScripts.ClientJournal(ownerSid,id);
    bool networkJournal=NetworkScripts.HasJournal(ownerSid,id);
    bool clientRecorded=File.Exists(journalPath);
    try{
     File.Delete(NetworkScripts.HookLease(ownerSid,id));
     StopSavedClient(journalPath);
     if(Script(folder,"Cleanup",ownerSid:ownerSid)!=0)
      throw new IOException("Не удалось подтвердить восстановление сети.");
     if(clientRecorded)File.Delete(journalPath);
     if(ownerSid==sid)recovered.Add(new(id,networkJournal,clientRecorded));
    }catch(Exception error) when(error is IOException or UnauthorizedAccessException or Win32Exception or JsonException or InvalidOperationException) {
     failures++;
    }
   }
   Storage.Save(Path.Combine(resultFolder,"recovered-sessions.json"),recovered);
   if(failures>0)throw new IOException("Не удалось очистить все сеансы VPN. Повторите восстановление сети.");
   State(resultFolder,"disconnected",sessions.Length==0?"Незавершённых сетевых изменений не найдено.":"Сеть восстановлена.",restored:true);
   return 0;
  }catch(Exception error){
   TryState(resultFolder,"recovery_required",error.Message);
   return 1;
  }finally{
   if(locked)mutex.ReleaseMutex();
  }
 }
 internal static int Run(string id,int parentId,long parentTicks,bool bootstrap)
 {
  using var identity=WindowsIdentity.GetCurrent();
  if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
  using var parent=OpenParent(parentId,parentTicks,identity.User!,bootstrap);
  if(parent is null)return AccountMismatchExitCode;
  string sid=identity.User!.Value,folder=NetworkScripts.SessionPath(sid,id);
  using var mutex=new Mutex(false,SessionMutexName); bool locked=false;
  Process? vpn=null;
  EventWaitHandle? stop=null;
  TunnelPacketMonitor? activity=null;
  bool cleaned=false,scriptsReady=false,cleanupRequired=false,recoveryPending=false;
  string? clientJournal=null;
  string failure="";
  var peerCounters=new TunnelActivity.RecentPeers();
  bool StopRequested()=>consoleStop||parent is {HasExited:true}||stop?.WaitOne(0)==true;
  IOException NetworkFailure(string message){cleanupRequired=true;return new IOException(message);}
  try {
   NetworkScripts.PrepareSession(sid,id);
   try { locked=mutex.WaitOne(0); } catch(AbandonedMutexException) { locked=true; }
   if(!locked) throw new IOException("Другой сеанс VPN ещё выполняется.");
   NetworkScripts.Prepare();
   if(bootstrap)NetworkScripts.InstallWorker(Environment.ProcessPath!);
   // Protected records survive the loss of an entire per-user session directory.
   recoveryPending=NetworkScripts.PendingSessions(NetworkScripts.StateDirectory).Any() ||
    Storage.SessionsWithRecoveryFiles().Any(previousId=>previousId!=id);
   if(recoveryPending)throw new IOException("Есть незавершённый сеанс. Нажмите «Восстановить сеть».");
   scriptsReady=true;
   clientJournal=NetworkScripts.ClientJournal(sid,id);
   stop=EventWaitHandle.OpenExisting(StopName(id));
   string inputFolder=Storage.SessionPath(id);
   Config config=Storage.Read<Config>(Path.Combine(inputFolder,"config.json")); config.Validate();
   Storage.Save(Path.Combine(folder,"config.json"),config);
   if(StopRequested()) throw new OperationCanceledException();
   using(var setupTimeout=new CancellationTokenSource(TimeSpan.FromMinutes(10))){
    var setup=Task.Run(()=>RuntimeSetup.EnsureProtected(message=>TryState(folder,"preparing",message),setupTimeout.Token));
    while(!setup.IsCompleted){
     if(StopRequested())setupTimeout.Cancel();
     Thread.Sleep(100);
    }
    try{setup.GetAwaiter().GetResult();}
    catch(OperationCanceledException) when(!StopRequested()){throw new IOException("Загрузка VPN-компонентов не завершилась за отведённое время.");}
   }
   if(StopRequested())throw new OperationCanceledException();
   NativeAuth.RuntimeDirectory=NetworkScripts.RuntimeDirectory;
   State(folder,"authenticating","Введите данные входа в окне приложения.");
   int authStep=0;
   var authTrace=new List<object>();
   void TraceAuth(string evt){lock(authTrace){if(authTrace.Count>=160)return;authTrace.Add(new{Event=evt,UpdatedUtc=DateTime.UtcNow});Storage.Save(Path.Combine(folder,"auth-trace.json"),authTrace);}}
   AuthSession login=AuthPipe.Login(id,parentId,config,StopRequested,(phase,notice)=>{
    lock(authTrace){
    // Fixed phase names only: never log forms, replies, credentials or cookies.
    Storage.Save(Path.Combine(folder,"auth-stage.json"),new{Phase=phase,Step=++authStep,UpdatedUtc=DateTime.UtcNow});
    TraceAuth(phase);
    string message=notice??(phase switch{
     "form_requested"=>"Введите данные, запрошенные VPN, в окне приложения.",
     "code_submitted"=>$"Код отправлен. Ждём ответ VPN до {AuthResponseWait.CodeWaitSeconds} секунд…",
     "form_submitted"=>"Ожидаем подтверждение от сервера VPN…",
     "cookie_obtained"=>"Сервер VPN подтвердил вход. Подготавливаем туннель…",
     _=>"Ожидаем ответ сервера VPN…"
    });
    State(folder,"authenticating",message);
    }
   },TraceAuth);
   if(StopRequested())throw new OperationCanceledException();
   if(!AllocConsole() || !SetConsoleCtrlHandler(handler,true)) throw new IOException("Не удалось подготовить VPN-процесс.");
   using(File.Open(NetworkScripts.HookLease(sid,id),FileMode.CreateNew)){ }
   ShowWindow(GetConsoleWindow(),0);
   string clientDirectory=Path.Combine(NetworkScripts.RuntimeDirectory,"client");
   var info=new ProcessStartInfo(Path.Combine(clientDirectory,"openconnect.exe")) { UseShellExecute=false,WorkingDirectory=clientDirectory,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true };
   NetworkScripts.SetSystemEnvironment(info,NetworkScripts.RuntimeDirectory);
   foreach(var arg in new[]{"--protocol=fortinet","--interface="+TunnelTraffic.AdapterName,"--disable-ipv6","--no-proxy","--no-dtls","--force-dpd=60","--reconnect-timeout=60","--non-inter","--cookie-on-stdin","--resolve",login.Resolve,"--script",NetworkScripts.Hook}) info.ArgumentList.Add(arg);
   if(config.User.Length>0) { info.ArgumentList.Add("--user");info.ArgumentList.Add(config.User); }
   info.ArgumentList.Add(login.ConnectUrl);info.Environment["FORTISPLIT_SESSION"]=folder;
   // OpenConnect can reuse an existing adapter with counters from a previous session.
   var existingCounters=TunnelTraffic.Read();
   vpn=Process.Start(info) ?? throw new IOException("OpenConnect не запустился.");
   var savedClient=new VpnProcess(vpn.Id,vpn.StartTime.ToUniversalTime().Ticks,info.FileName);
   Storage.Save(clientJournal,savedClient);
   vpn.StandardInput.WriteLine(login.Cookie);vpn.StandardInput.Close();login=new("","","");
   _=Drain(vpn.StandardOutput);_=Drain(vpn.StandardError);
   State(folder,"preparing","Вход выполнен. Создаём рабочий туннель…");
   string generation="";
   string lastWorkRequest="";
   TunnelCounters? trafficStart=null;
   Status? connectedStatus=null;
   long nextPeerSample=0;
   string statusPath=Path.Combine(folder,"status.json");
   var dnsRetries=new WorkDnsRetries();
   bool deferredDns=false;
   long? waitingForNetwork=Stopwatch.GetTimestamp();
   bool SessionActive()=>!vpn.HasExited&&!StopRequested();
   bool? ShowNetworkReady(string expectedGeneration){
    if(NetworkReconnecting(folder)||NetworkHookFailed(folder)||
       ReadNetwork(folder) is not {Stage:"ready"} network||network.Generation!=expectedGeneration)return null;
    generation=expectedGeneration;
     waitingForNetwork=null;
    trafficStart=null;
    if(Guid.TryParse(network.Guid,out var adapterId))
     trafficStart=existingCounters?.AdapterId==adapterId?existingCounters:new(adapterId,0,0);
    int unresolved=network.Unresolved?.Length??0;
    deferredDns=network.Deferred is {Length:>0};
    string message="VPN подключён."+network.GatewayConflictNotice;
    if(unresolved>0)message+=$" Не удалось определить адреса: {unresolved}. Повторите попытку в настройках.";
    WorkTrafficSnapshot? workTraffic=null;
    peerCounters.Replace(network.Peers());
    if(activity is not {IsRunning:true}){
     activity?.Dispose();
     var completed=peerCounters.Finish();
     activity=TunnelActivity.Start(network,peerCounters);
     nextPeerSample=Stopwatch.GetTimestamp()+Stopwatch.Frequency;
     workTraffic=completed with{CaptureAvailable=activity is {IsRunning:true}};
    }
    workTraffic??=activity is {IsRunning:true}?connectedStatus?.WorkTraffic??peerCounters.Snapshot():peerCounters.Finish();
    connectedStatus=new("connected",message,true,TrafficStart:trafficStart,WorkTraffic:workTraffic,NetworkGeneration:generation);
    Storage.Save(statusPath,connectedStatus);return unresolved>0;
   }
   void RefreshWorkTraffic(){
    if(connectedStatus is null)return;
    long now=Stopwatch.GetTimestamp();
    if(now<nextPeerSample)return;
    nextPeerSample=now+Stopwatch.Frequency;
    var traffic=activity is {IsRunning:true}?peerCounters.Snapshot():peerCounters.Finish();
    var previous=connectedStatus.WorkTraffic;
    if(traffic.Peers.Length==0&&previous is {Peers.Length:0}&&traffic.CaptureAvailable==previous.CaptureAvailable&&
      (traffic.RecentEvents??[]).SequenceEqual(previous.RecentEvents??[]))return;
    var updated=connectedStatus with{WorkTraffic=traffic};
    try{Storage.Save(statusPath,updated);connectedStatus=updated;}
    catch(Exception error) when(error is IOException or UnauthorizedAccessException){ }
   }
   while(SessionActive()) {
    if(NetworkHookFailed(folder))
     throw NetworkFailure("Не удалось настроить сеть VPN. Смотрите network-hook-error.txt.");
    if(waitingForNetwork is long started&&Stopwatch.GetElapsedTime(started)>=NetworkReadyLimit)
     throw NetworkFailure("Настройка сети VPN не завершилась за отведённое время.");
    if(NetworkReconnecting(folder)){
     waitingForNetwork??=Stopwatch.GetTimestamp();
     if(connectedStatus is not null){
      activity?.Dispose();activity=null;connectedStatus=null;
      TryState(folder,"reconnecting","Восстанавливаем соединение и сетевые настройки…",workTraffic:peerCounters.Finish());
     }
     Thread.Sleep(500);
     continue;
    }
    if(ReadNetwork(folder) is {Stage:"base_ready",Generation:{ } current} && current!=generation) {
     waitingForNetwork??=Stopwatch.GetTimestamp();
     activity?.Dispose();activity=null;connectedStatus=null;
     TryState(folder,"configuring","Настраиваем маршруты и DNS VPN…");
     int outcome=Script(folder,"Resolve",current);
     if(outcome==NetworkGenerationChanged)continue;
     if(outcome!=0)throw NetworkFailure("Не удалось настроить рабочие адреса. Смотрите network-error.txt.");
     if(!SessionActive()) break;
     if(ShowNetworkReady(current) is not bool unresolved)continue;
     dnsRetries.Reset(unresolved,DateTime.UtcNow);
    }
    if(connectedStatus is not null&&SessionActive()){
     string requestPath=Path.Combine(inputFolder,"work-address-request.json");
     if(File.Exists(requestPath)){
      var request=Storage.Read<WorkAddressRequest>(requestPath);
      if(request.Id!=lastWorkRequest){
       int outcome=0;
       var activeConfig=Storage.Read<Config>(Path.Combine(folder,"config.json"));
       var result=request.ApplyToSession(activeConfig,SessionActive,updated=>{
        TryState(folder,"configuring","Обновляем маршруты и DNS рабочих адресов…");
        Storage.Save(Path.Combine(folder,"candidate-config.json"),updated);
         outcome=Script(folder,"Apply",generation);
        if(outcome is not (0 or NetworkChangeRejected or NetworkGenerationChanged))
         throw NetworkFailure("Не удалось восстановить сетевые настройки после обновления. Смотрите network-error.txt.");
       },()=>{
        if(outcome!=NetworkGenerationChanged&&ShowNetworkReady(generation) is bool unresolved)dnsRetries.Reset(unresolved,DateTime.UtcNow);
       });
       if(result is null||!SessionActive())break;
       if(outcome==NetworkGenerationChanged)continue;
       if(outcome==NetworkChangeRejected)
        result=new(request.Id,false,"Изменения не применены. Прежние маршруты и DNS сохранены. Подробности — в network-error.txt.");
       else if(result.Success&&ReadNetwork(folder) is { } applied)
        result=result with {Message=result.Message+applied.GatewayConflictNotice};
       Storage.Save(Path.Combine(folder,"work-address-result.json"),result);
       lastWorkRequest=request.Id;
      }
     }
     if(deferredDns||dnsRetries.TakeDue(DateTime.UtcNow)){
      bool continuing=deferredDns;
       int outcome=Script(folder,continuing?"Continue":"Retry",generation);
      if(outcome==NetworkGenerationChanged)continue;
      if(outcome is not (0 or NetworkChangeRejected))throw NetworkFailure("Не удалось обновить рабочие адреса. Смотрите network-error.txt.");
      if(!SessionActive())break;
      if(ShowNetworkReady(generation) is bool unresolved){
       if(continuing)dnsRetries.Reset(unresolved,DateTime.UtcNow);
       else dnsRetries.Complete(unresolved);
       // A rejected route change leaves the previous journal intact. Resume only bounded retries.
       if(!continuing||outcome==NetworkChangeRejected)deferredDns=false;
      }
     }
    }
    RefreshWorkTraffic();
    Thread.Sleep(500);
   }
   if(vpn.HasExited && !StopRequested()){
    if(NetworkHookFailed(folder))throw NetworkFailure("Не удалось настроить сеть VPN. Смотрите network-hook-error.txt.");
     cleanupRequired=generation.Length==0;
    var error=VpnExitError.Describe(vpn.ExitCode,generation.Length>0);failure=error.Message;
    Storage.Save(Path.Combine(folder,"vpn-exit.json"),new{ExitCode=vpn.ExitCode,Phase=generation.Length>0?"tunnel_active":"creating_tunnel",Reason=error.Kind,UpdatedUtc=DateTime.UtcNow});
   }
  } catch(OperationCanceledException) { failure="Вход отменён."; }
  catch(Exception e) {
   failure=e.Message;
   cleanupRequired|=vpn is {HasExited:false};
   if(!locked)TryState(folder,"recovery_required",failure);
  }
  finally {
   activity?.Dispose();
   var lastTraffic=peerCounters.Finish();
   if(locked) {
    try {
     if(scriptsReady)File.Delete(NetworkScripts.HookLease(sid,id));
     if((StopRequested()||cleanupRequired) && scriptsReady){
      TryState(folder,"disconnecting","Отключаем VPN и восстанавливаем настройки…",workTraffic:lastTraffic);
      if(vpn is not null && !vpn.HasExited){GenerateConsoleCtrlEvent(0,0);if(!vpn.WaitForExit(10000))StopProcess(vpn);}
      cleaned=Script(folder,"Cleanup")==0;
      if(cleaned&&clientJournal is not null)File.Delete(clientJournal);
      string message=failure.Length>0?failure:"VPN отключён.";
      TryState(folder,cleaned?(cleanupRequired?"error":"disconnected"):"recovery_required",
       message+(cleaned?" Сетевые настройки восстановлены.":" Нажмите «Восстановить сеть»."),restored:cleaned,workTraffic:lastTraffic);
     }else{
      bool pending=recoveryPending||File.Exists(Path.Combine(folder,"network.json"))||
       (scriptsReady && NetworkScripts.HasJournal(sid,id))||(vpn is not null&&!vpn.HasExited);
      if(!pending&&clientJournal is not null)File.Delete(clientJournal);
      State(folder,pending?"recovery_required":"error",failure,restored:!pending,workTraffic:lastTraffic);
     }
    } catch(Exception e) { try { State(folder,"recovery_required","Ошибка завершения: "+e.Message); } catch(Exception) { } }
   }
   vpn?.Dispose();stop?.Dispose();if(locked) mutex.ReleaseMutex();
  }
  return cleaned&&!cleanupRequired?0:1;
 }
}
