using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace FortiSplit.Work;

internal sealed record UpdateMarker(string OriginExe);
internal sealed record UpdateLink(string OriginExe,string TargetExe,bool Pending=false,UpdateLink? Previous=null,string? TargetSha256=null);
internal sealed record UpdateTicket(string OriginExe,string CurrentExe,int ParentId,long ParentTicks);

internal static class UpdateInstall
{
 private const string GateName=@"Local\FortiSplitWork-Update";
 internal const string ProofArchive=".fortisplit-release.zip",ProofSignature=ProofArchive+".sig",
  ProofAttestation=ProofArchive+UpdateCatalog.AttestationSuffix;
 private static string Updates=>Path.Combine(Storage.Root,"updates");
 private static string Versions=>Path.Combine(Updates,"versions");
 private static string Staging=>Path.Combine(Updates,"staging");
 private static string Links=>Path.Combine(Updates,"links");
 private static bool Equal(string a,string b)=>string.Equals(Path.GetFullPath(a),Path.GetFullPath(b),StringComparison.OrdinalIgnoreCase);
 private static bool Within(string path,string root)=>Path.GetFullPath(path).StartsWith(Path.GetFullPath(root)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
 private static Version ProductVersion(string path){
  var version=FileVersionInfo.GetVersionInfo(path);
  return new(version.ProductMajorPart,version.ProductMinorPart,version.ProductBuildPart);
 }
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

 [DllImport("kernel32.dll",EntryPoint="CreateFileW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]
 private static extern SafeFileHandle OpenPath(string path,uint access,FileShare sharing,IntPtr security,
  FileMode mode,uint flags,IntPtr template);

 internal sealed class VerifiedExecutable(string path,FileStream image,List<SafeFileHandle> directories):IDisposable
 {
  internal string Path {get;}=path;
  internal UpdateLink CreateLink(string origin)
  {
   // The original 1.2.7 shortcut still checks this field on every launch.
   image.Position=0;
   return new(origin,Path,TargetSha256:Convert.ToHexString(SHA256.HashData(image)));
  }

  public void Dispose()
  {
   image.Dispose();
   foreach(var directory in directories)directory.Dispose();
  }
 }

 private static void VerifyProof(Stream content,string attestationPath,string signaturePath,string? publisherKey)
 {
  if(File.Exists(attestationPath)){
   Storage.RegularPath(attestationPath);
   byte[] proof=UpdateAttestation.Read(attestationPath);
   Task.Run(()=>UpdateAttestation.Verify(content,proof,CancellationToken.None)).GetAwaiter().GetResult();
   return;
  }
  if(string.IsNullOrEmpty(publisherKey)||!File.Exists(signaturePath))
   throw new IOException("Подтверждение обновления отсутствует. Распакуйте ZIP выпуска в отдельную папку и запустите «Forti Split.exe» оттуда.");
  Storage.RegularPath(signaturePath);
  using var signature=File.OpenRead(signaturePath);
  if(signature.Length is <384 or >512)throw new IOException("Неверный размер подписи обновления.");
  byte[] signatureBytes=new byte[(int)signature.Length];signature.ReadExactly(signatureBytes);
  if(!UpdateDownload.VerifyPublisher(publisherKey,Convert.ToHexString(SHA256.HashData(content)),signatureBytes))
   throw new IOException("Подпись издателя обновления не прошла проверку.");
 }

 internal static VerifiedExecutable OpenVerifiedExecutable(string path,string? publisherKey)
 {
  const uint directoryAccess=1,readAccess=0x80000000,backupSemantics=0x02000000,openReparsePoint=0x00200000;
  path=Path.GetFullPath(path);
  string directory=Path.GetDirectoryName(path)!;
  var parents=new Stack<string>();
  for(var parent=new DirectoryInfo(directory);parent is not null;parent=parent.Parent)parents.Push(parent.FullName);
  var lockedDirectories=new List<SafeFileHandle>();
  FileStream? executable=null;
  try{
   // Hold each path component against rename or replacement until CreateProcess has opened it.
   foreach(string parent in parents){
    var handle=OpenPath(parent,directoryAccess,FileShare.ReadWrite,IntPtr.Zero,FileMode.Open,backupSemantics|openReparsePoint,IntPtr.Zero);
    lockedDirectories.Add(handle);
    if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
    Storage.RegularPath(parent);
   }
   var image=OpenPath(path,readAccess,FileShare.Read,IntPtr.Zero,FileMode.Open,openReparsePoint,IntPtr.Zero);
   try{
    if(image.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
    Storage.RegularPath(path);
    executable=new FileStream(image,FileAccess.Read);
   }catch{image.Dispose();throw;}
   string archivePath=Path.Combine(directory,ProofArchive);
   if(File.Exists(archivePath)){
    Storage.RegularPath(archivePath);
    using var archive=File.OpenRead(archivePath);
    if(archive.Length is <=0 or >200L*1024*1024)throw new IOException("Неверный размер данных проверки обновления.");
    VerifyProof(archive,Path.Combine(directory,ProofAttestation),Path.Combine(directory,ProofSignature),publisherKey);
    archive.Position=0;
    if(!UpdateArchive.MatchesExecutable(archive,executable))throw new IOException("Файл приложения отличается от подписанного выпуска.");
   }else{
    // Legacy installers discard the ZIP. Their format allows extra files under licenses/.
    string proof=Path.Combine(directory,"licenses","FortiSplit.exe");
    VerifyProof(executable,proof+UpdateCatalog.AttestationSuffix,proof+".sig",publisherKey);
   }
   return new(path,executable,lockedDirectories);
  }catch{
   executable?.Dispose();
   foreach(var parent in lockedDirectories)parent.Dispose();
   throw;
  }
 }

 internal static IDisposable OpenBootstrapExecutable(string path)
 {
  if(Within(path,Versions))return OpenVerifiedExecutable(path,UpdateDownload.PublisherKey);
  Storage.RegularPath(path);
  return File.OpenRead(path);
 }

 internal static VerifiedExecutable? ForwardTarget(bool allowPending=false)
 {
  try{
   string current=Environment.ProcessPath??throw new IOException();string origin=Origin(current);string path=LinkPath(origin);
   if(!File.Exists(path))return null;
   var link=Storage.Read<UpdateLink>(path);
   if(link.Pending&&!allowPending){
    if(link.Previous is null){File.Delete(path);return null;}
    Storage.Save(path,link.Previous);link=link.Previous;
   }
   if(!Equal(link.OriginExe,origin)||!Within(link.TargetExe,Versions)||Path.GetFileName(link.TargetExe)!="Forti Split.exe"||Equal(current,link.TargetExe))return null;
   var executable=OpenVerifiedExecutable(link.TargetExe,UpdateDownload.PublisherKey);
   try{if(ProductVersion(executable.Path)>ProductVersion(current))return executable;}
   catch{executable.Dispose();throw;}
   executable.Dispose();return null;
  }catch(Exception){return null;}
 }

 internal static bool IsUpdateLaunch()
 {
  string? id=Environment.GetEnvironmentVariable("FORTISPLIT_UPDATE_READY");
  if(!Guid.TryParseExact(id,"N",out _))return false;
  try{using var ready=EventWaitHandle.OpenExisting(@"Local\FortiSplitUpdateStarted-"+id);return true;}catch(WaitHandleCannotBeOpenedException){return false;}
 }

 internal static bool CanConfirmLaunch(string? path,string? publisherKey)
 {
  // Check this build's proof before the previous installer commits the link.
  if(path is null)return false;
  try{
   using var executable=OpenVerifiedExecutable(path,publisherKey);
   return true;
  }catch(Exception error) when(error is IOException or UnauthorizedAccessException or Win32Exception or CryptographicException or FormatException){return false;}
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
   if(link.Pending||!Equal(link.OriginExe,origin)||!Equal(link.TargetExe,current))return false;
   using var executable=OpenVerifiedExecutable(current,UpdateDownload.PublisherKey);
   return true;
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
   byte[] proof=await UpdateDownload.DownloadProof(release,cancellation);
   string archive=Path.Combine(temporary,"release.zip");await UpdateDownload.Download(release,archive,cancellation);
   if(release.HasBuildAttestation){
    using var downloaded=File.OpenRead(archive);
    await UpdateAttestation.Verify(downloaded,proof,cancellation);
   }
   cancellation.ThrowIfCancellationRequested();
   await Task.Run(()=>{
     UpdateArchive.Extract(archive,version);Storage.Protect(version);
     string executable=Path.Combine(version,"Forti Split.exe");
     if(UpdateCatalog.CurrentVersion(FileVersionInfo.GetVersionInfo(executable).ProductVersion??"")!=release.Version)
      throw new IOException("Версия подписанного приложения не совпадает с выпуском.");
    string client=Path.Combine(Path.GetDirectoryName(current)!,"client");Storage.RegularPath(client);
    if(Directory.Exists(client))UpdateRuntime.Copy(client,Path.Combine(version,"client"));
    Storage.Save(Path.Combine(version,".fortisplit-origin.json"),new UpdateMarker(origin));
    File.Move(archive,Path.Combine(version,ProofArchive));
    File.WriteAllBytes(Path.Combine(version,release.HasBuildAttestation?ProofAttestation:ProofSignature),proof);
   },cancellation);
   cancellation.ThrowIfCancellationRequested();
   using var parent=Process.GetCurrentProcess();
   Storage.Save(Path.Combine(temporary,"ticket.json"),new UpdateTicket(origin,current,parent.Id,parent.StartTime.ToUniversalTime().Ticks));
   using var ready=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\FortiSplitUpdateReady-"+id);
   var info=new ProcessStartInfo(current){UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--complete-update");info.ArgumentList.Add(id);
   using var child=Process.Start(info)??throw new IOException("Не удалось запустить обновление.");
   if(!await Task.Run(()=>ready.WaitOne(TimeSpan.FromSeconds(30)),cancellation)){try{child.Kill();}catch(Exception){}throw new IOException("Не удалось запустить обновление.");}
   if(cancellation.IsCancellationRequested){try{child.Kill();}catch(Exception){}cancellation.ThrowIfCancellationRequested();}
   launched=true;
  }finally{
   if(!launched){try{Directory.Delete(version,true);}catch(Exception){}try{Directory.Delete(temporary,true);}catch(Exception){}}
  }
 }

 internal static int Complete(string id)=>Complete(id,Updates,GateName,Environment.ProcessPath!,UpdateDownload.PublisherKey,
  _=>MessageBox.Show("Не удалось завершить обновление. Прежняя версия сохранена.","Forti Split",MessageBoxButtons.OK,MessageBoxIcon.Error),
  current=>{using var image=OpenBootstrapExecutable(current);Process.Start(new ProcessStartInfo(current){UseShellExecute=false})?.Dispose();});

 internal static int Complete(string id,string updates,string gateName,string current,string? publisherKey,Action<Exception> reportFailure,Action<string> restart)
 {
  if(!Guid.TryParseExact(id,"N",out _))return 1;
  string versions=Path.Combine(updates,"versions");
  string temporary=Path.Combine(updates,"staging",id),version=Path.Combine(versions,id);
  using var gate=new Mutex(false,gateName);bool locked=false,parentExited=false;UpdateTicket? ticket=null;
  try{
   try{locked=gate.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
   if(!locked)throw new IOException("Уже выполняется обновление.");
   ticket=Storage.Read<UpdateTicket>(Path.Combine(temporary,"ticket.json"));
   string target=Path.Combine(version,"Forti Split.exe");
   if(!Equal(ticket.CurrentExe,current)||!Equal(Origin(current,versions),ticket.OriginExe)||!Equal(Origin(target,versions),ticket.OriginExe))
    throw new IOException("Не удалось проверить подготовленное обновление.");
   using var executable=OpenVerifiedExecutable(target,publisherKey);
   if(ProductVersion(target)<=ProductVersion(current))throw new IOException("Подготовленное обновление не новее текущей версии.");
   using(var ready=EventWaitHandle.OpenExisting(@"Local\FortiSplitUpdateReady-"+id))ready.Set();
   try{using var parent=Process.GetProcessById(ticket.ParentId);if(!parent.HasExited&&(parent.StartTime.ToUniversalTime().Ticks!=ticket.ParentTicks||!Equal(parent.MainModule?.FileName??"",ticket.CurrentExe)||!parent.WaitForExit(30000)))throw new IOException("Приложение не завершилось.");}catch(ArgumentException){}parentExited=true;
   string path=LinkPath(ticket.OriginExe,Path.Combine(updates,"links"));UpdateLink? previous=File.Exists(path)?Storage.Read<UpdateLink>(path):null;
   if(previous?.Pending==true)throw new IOException("Предыдущее обновление не завершено.");
   var committed=executable.CreateLink(ticket.OriginExe);
   Storage.Save(path,committed with {Pending=true,Previous=previous});
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
    Storage.Save(path,committed);
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
