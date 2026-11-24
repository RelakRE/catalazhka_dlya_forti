using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace FortiSplit.Work;

internal sealed record UpdateMarker(string OriginExe);
internal sealed record UpdateLink(string OriginExe,string TargetExe,string TargetSha256,bool Pending=false,UpdateLink? Previous=null);
internal sealed record UpdateTicket(string OriginExe,string CurrentExe,string TargetSha256,int ParentId,long ParentTicks);

internal static class UpdateInstall
{
 private const string GateName=@"Local\FortiSplitWork-Update";
 private static string Updates=>Path.Combine(Storage.Root,"updates");
 private static string Versions=>Path.Combine(Updates,"versions");
 private static string Staging=>Path.Combine(Updates,"staging");
 private static string Links=>Path.Combine(Updates,"links");
 private static bool Equal(string a,string b)=>string.Equals(Path.GetFullPath(a),Path.GetFullPath(b),StringComparison.OrdinalIgnoreCase);
 private static bool Within(string path,string root)=>Path.GetFullPath(path).StartsWith(Path.GetFullPath(root)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
 private static string Hash(string path){using var stream=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(stream));}
 private static string LinkPath(string origin)=>LinkPath(origin,Links);
 internal static string LinkPath(string origin,string links)=>Path.Combine(links,Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(origin).ToUpperInvariant())))+".json");

 private static string Origin(string current)=>Origin(current,Versions);
 private static string Origin(string current,string versions)
 {
  current=Path.GetFullPath(current);Storage.RegularPath(current);
  if(Within(current,versions)){
   string marker=Path.Combine(Path.GetDirectoryName(current)!,".fortisplit-origin.json");
   var data=Storage.Read<UpdateMarker>(marker);
   if(!Path.IsPathFullyQualified(data.OriginExe)||!data.OriginExe.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new IOException("Неверные сведения об установке.");
   return Path.GetFullPath(data.OriginExe);
  }
  return current;
 }

 internal static string? ForwardTarget(bool allowPending=false)
 {
  try{
   string current=Environment.ProcessPath??throw new IOException();string origin=Origin(current);string path=LinkPath(origin);
   if(!File.Exists(path))return null;
   var link=Storage.Read<UpdateLink>(path);
   if(link.Pending&&!allowPending){
    if(link.Previous is null){File.Delete(path);return Equal(current,origin)||!File.Exists(origin)?null:origin;}
    Storage.Save(path,link.Previous);link=link.Previous;
   }
   if(!Equal(link.OriginExe,origin)||!Within(link.TargetExe,Versions)||Path.GetFileName(link.TargetExe)!="Forti Split.exe")return null;
   Storage.RegularPath(link.TargetExe);
   if(!File.Exists(link.TargetExe)||!string.Equals(Hash(link.TargetExe),link.TargetSha256,StringComparison.OrdinalIgnoreCase))return null;
   if(Equal(current,link.TargetExe))return null;
   return link.TargetExe;
  }catch(Exception){return null;}
 }

 internal static bool IsUpdateLaunch()
 {
  string? id=Environment.GetEnvironmentVariable("FORTISPLIT_UPDATE_READY");
  if(!Guid.TryParseExact(id,"N",out _))return false;
  try{using var ready=EventWaitHandle.OpenExisting(@"Local\FortiSplitUpdateStarted-"+id);return true;}catch(WaitHandleCannotBeOpenedException){return false;}
 }

 internal static void SignalReady()
 {
  string? id=Environment.GetEnvironmentVariable("FORTISPLIT_UPDATE_READY");
  if(!Guid.TryParseExact(id,"N",out _))return;
  try{using var ready=EventWaitHandle.OpenExisting(@"Local\FortiSplitUpdateStarted-"+id);ready.Set();_ = Task.Run(async()=>{await Task.Delay(TimeSpan.FromSeconds(15));RemoveStaging(id!);});}catch(WaitHandleCannotBeOpenedException){}finally{Environment.SetEnvironmentVariable("FORTISPLIT_UPDATE_READY",null);}
 }

 internal static Task<bool> WaitForCommit()=>Task.Run(()=>{
  using var gate=new Mutex(false,GateName);bool locked=false;
  try{
   try{locked=gate.WaitOne(TimeSpan.FromSeconds(45));}catch(AbandonedMutexException){locked=true;}
   if(!locked)return false;
   string current=Environment.ProcessPath??throw new IOException();string origin=Origin(current);
   var link=Storage.Read<UpdateLink>(LinkPath(origin));
   return !link.Pending&&Equal(link.OriginExe,origin)&&Equal(link.TargetExe,current);
  }catch(Exception){return false;}finally{if(locked)gate.ReleaseMutex();}
 });

 private static void RemoveStaging(string id)
 {
  if(!Guid.TryParseExact(id,"N",out _))return;
  try{string path=Path.Combine(Staging,id);Storage.RegularPath(path);if(Directory.Exists(path))Directory.Delete(path,true);}catch(Exception){}
 }

 internal static void RemoveOldStaging()
 {
  try{if(!Directory.Exists(Staging))return;Storage.RegularPath(Staging);foreach(string path in Directory.EnumerateDirectories(Staging)){
   if(Guid.TryParseExact(Path.GetFileName(path),"N",out _)&&Directory.GetLastWriteTimeUtc(path)<DateTime.UtcNow.AddDays(-1))RemoveStaging(Path.GetFileName(path));
  }}catch(Exception){}
 }

 internal static bool ResetForward(string expected)
 {
  using var gate=AcquireLaunchGate();if(gate is null)return false;
  try{
   string origin=Origin(Environment.ProcessPath??throw new IOException());string path=LinkPath(origin);
   if(!File.Exists(path))return true;
   var link=Storage.Read<UpdateLink>(path);
   if(!Equal(link.OriginExe,origin)||!Equal(link.TargetExe,expected))return false;
   File.Delete(path);return true;
  }catch(Exception){return false;}finally{gate.ReleaseMutex();}
 }

 internal static async Task Stage(UpdateCandidate release,CancellationToken cancellation)
 {
  string current=Environment.ProcessPath??throw new IOException("Не удалось определить приложение.");
  string origin=Origin(current);string id=Guid.NewGuid().ToString("N");
  Storage.Protect(Updates);Storage.Protect(Staging);Storage.Protect(Versions);Storage.Protect(Links);
  string temporary=Path.Combine(Staging,id),version=Path.Combine(Versions,id);Storage.Protect(temporary);
  bool launched=false;
  try{
   string archive=Path.Combine(temporary,"release.zip");await UpdateDownload.Download(release,archive,cancellation);
   cancellation.ThrowIfCancellationRequested();
   await Task.Run(()=>{
    UpdateArchive.Extract(archive,version);Storage.Protect(version);
    string client=Path.Combine(Path.GetDirectoryName(current)!,"client");Storage.RegularPath(client);
    UpdateRuntime.Copy(client,Path.Combine(version,"client"));
    Storage.Save(Path.Combine(version,".fortisplit-origin.json"),new UpdateMarker(origin));
   },cancellation);
   cancellation.ThrowIfCancellationRequested();
   string target=Path.Combine(version,"Forti Split.exe");Storage.RegularPath(target);
   using var parent=Process.GetCurrentProcess();
   string targetHash=await Task.Run(()=>Hash(target),cancellation);
   Storage.Save(Path.Combine(temporary,"ticket.json"),new UpdateTicket(origin,current,targetHash,parent.Id,parent.StartTime.ToUniversalTime().Ticks));
   File.Delete(archive);string helper=Path.Combine(temporary,"updater.exe");await Task.Run(()=>File.Copy(current,helper),cancellation);
   using var ready=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\FortiSplitUpdateReady-"+id);
   var info=new ProcessStartInfo(helper){UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--complete-update");info.ArgumentList.Add(id);
   using var child=Process.Start(info)??throw new IOException("Не удалось запустить обновление.");
   if(!await Task.Run(()=>ready.WaitOne(TimeSpan.FromSeconds(10)),cancellation)){try{child.Kill();}catch(Exception){}throw new IOException("Не удалось запустить обновление.");}
   if(cancellation.IsCancellationRequested){try{child.Kill();}catch(Exception){}cancellation.ThrowIfCancellationRequested();}
   launched=true;
  }finally{
   if(!launched){try{Directory.Delete(version,true);}catch(Exception){}try{Directory.Delete(temporary,true);}catch(Exception){}}
  }
 }

 internal static int Complete(string id)=>Complete(id,Updates,GateName,
  _=>MessageBox.Show("Не удалось завершить обновление. Прежняя версия сохранена.","Forti Split",MessageBoxButtons.OK,MessageBoxIcon.Error),
  current=>Process.Start(new ProcessStartInfo(current){UseShellExecute=true})?.Dispose());

 internal static int Complete(string id,string updates,string gateName,Action<Exception> reportFailure,Action<string> restart)
 {
  if(!Guid.TryParseExact(id,"N",out _))return 1;
  string versions=Path.Combine(updates,"versions");
  string temporary=Path.Combine(updates,"staging",id),version=Path.Combine(versions,id);
  using var gate=new Mutex(false,gateName);bool locked=false,parentExited=false;UpdateTicket? ticket=null;
  try{
   try{locked=gate.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
   if(!locked)throw new IOException("Уже выполняется обновление.");
   ticket=Storage.Read<UpdateTicket>(Path.Combine(temporary,"ticket.json"));
   string target=Path.Combine(version,"Forti Split.exe");Storage.RegularPath(target);
   if(!File.Exists(target)||!string.Equals(Hash(target),ticket.TargetSha256,StringComparison.OrdinalIgnoreCase)||!Equal(Origin(ticket.CurrentExe,versions),ticket.OriginExe)||!Equal(Origin(target,versions),ticket.OriginExe))throw new IOException("Не удалось проверить подготовленное обновление.");
   using(var ready=EventWaitHandle.OpenExisting(@"Local\FortiSplitUpdateReady-"+id))ready.Set();
   try{using var parent=Process.GetProcessById(ticket.ParentId);if(!parent.HasExited&&(parent.StartTime.ToUniversalTime().Ticks!=ticket.ParentTicks||!Equal(parent.MainModule?.FileName??"",ticket.CurrentExe)||!parent.WaitForExit(30000)))throw new IOException("Приложение не завершилось.");}catch(ArgumentException){}parentExited=true;
   string path=LinkPath(ticket.OriginExe,Path.Combine(updates,"links"));UpdateLink? previous=File.Exists(path)?Storage.Read<UpdateLink>(path):null;
   if(previous?.Pending==true)throw new IOException("Предыдущее обновление не завершено.");
   Storage.Save(path,new UpdateLink(ticket.OriginExe,target,ticket.TargetSha256,true,previous));
   Process? next=null;
   try{
    using var started=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\FortiSplitUpdateStarted-"+id);
    var info=new ProcessStartInfo(target){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=version};info.Environment["FORTISPLIT_UPDATE_READY"]=id;
    next=Process.Start(info)??throw new IOException("Не удалось открыть новую версию.");
    long start=Stopwatch.GetTimestamp();
    while(!started.WaitOne(100)){
     if(next.HasExited)throw new IOException("Новая версия завершилась до запуска.");
     if(Stopwatch.GetElapsedTime(start).TotalSeconds>=30)throw new IOException("Новая версия не открылась.");
    }
    Storage.Save(path,new UpdateLink(ticket.OriginExe,target,ticket.TargetSha256));
   }catch{try{if(next is not null&&!next.HasExited){next.Kill();next.WaitForExit();}}catch(Exception){}if(previous is null)File.Delete(path);else Storage.Save(path,previous);throw;}finally{next?.Dispose();}
   gate.ReleaseMutex();locked=false;
   return 0;
  }catch(Exception error){
   reportFailure(error);
   if(locked){gate.ReleaseMutex();locked=false;}
   if(parentExited&&ticket is not null)try{restart(ticket.CurrentExe);}catch(Exception){}
   return 1;
  }finally{if(locked)gate.ReleaseMutex();}
 }

 internal static Mutex? AcquireLaunchGate()
 {
  var gate=new Mutex(false,GateName);bool entered;
  try{try{entered=gate.WaitOne(0);}catch(AbandonedMutexException){entered=true;}}catch{gate.Dispose();throw;}
  if(!entered){gate.Dispose();return null;}return gate;
 }
}
