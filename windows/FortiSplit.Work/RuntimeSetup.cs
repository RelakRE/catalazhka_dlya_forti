using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;

namespace FortiSplit.Work;

// Dependencies are downloaded by the end user from upstream, never bundled in releases.
internal static class RuntimeSetup
{
 internal static bool Ready(string root) => new[]{"openconnect.exe","libopenconnect-5.dll","libgnutls-30.dll","wintun.dll"}.All(name=>File.Exists(Path.Combine(root,"client",name)));
 internal static bool Ensure()
 {
  if(Ready(AppContext.BaseDirectory))return true;
  using var window=new Form{Text="Подготовка Forti Split",ClientSize=new Size(570,190),StartPosition=FormStartPosition.CenterScreen,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=new Font("Segoe UI",10)};
  var label=new Label{Text="Подготовка VPN-компонентов из официальных загрузок…\nНужен доступ в интернет. Это выполняется один раз.",AutoSize=false,Bounds=new Rectangle(20,20,530,65)};
  var progress=new ProgressBar{Style=ProgressBarStyle.Marquee,Bounds=new Rectangle(20,95,530,20)};
  var cancel=new Button{Text="Отмена",Bounds=new Rectangle(430,135,120,32)};
  window.Controls.AddRange([label,progress,cancel]);
  using var cancellation=new CancellationTokenSource();bool completed=false,running=false;
  cancel.Click+=(_,_)=>{cancellation.Cancel();cancel.Enabled=false;};
  window.FormClosing+=(_,e)=>{if(running){e.Cancel=true;cancellation.Cancel();cancel.Enabled=false;}};
  window.Shown+=async(_,_)=>{
   running=true;
   try{await Install(AppContext.BaseDirectory,message=>label.Text=message,cancellation.Token);completed=true;}
   catch(OperationCanceledException){}
   catch(Exception){MessageBox.Show(window,"Не удалось подготовить VPN-компоненты. Проверьте интернет и распакуйте приложение в доступную для записи папку. Затем запустите снова.","Forti Split",MessageBoxButtons.OK,MessageBoxIcon.Error);}
   finally{running=false;window.Close();}
  };
  window.ShowDialog();return completed;
 }
 internal static async Task Install(string root,Action<string> progress,CancellationToken token)
 {
  root=Path.GetFullPath(root);
  if(Ready(root))return;
  string client=Path.Combine(root,"client");
  if(Directory.Exists(client)&&(File.GetAttributes(client)&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked runtime directory");
  string temporary=Path.Combine(root,".runtime-setup-"+Guid.NewGuid().ToString("N"));
  Directory.CreateDirectory(temporary);
  using var http=new HttpClient{Timeout=TimeSpan.FromMinutes(5)};
  try{
   async Task<string> Download(string name,string url,string sha){
    progress("Подготовка VPN-компонентов: "+name+"\nСоединение с VPN не выполняется.");
    string path=Path.Combine(temporary,name);
    using var response=await http.GetAsync(url,HttpCompletionOption.ResponseHeadersRead,token);response.EnsureSuccessStatusCode();
    if(response.Content.Headers.ContentLength>100*1024*1024)throw new IOException("Download too large");
    await using(var output=File.Create(path)){
     await using var input=await response.Content.ReadAsStreamAsync(token);byte[] buffer=new byte[65536];long total=0;int count;
     while((count=await input.ReadAsync(buffer,token))>0){total+=count;if(total>100*1024*1024)throw new IOException("Download too large");await output.WriteAsync(buffer.AsMemory(0,count),token);}
    }
    await using var file=File.OpenRead(path);string actual=Convert.ToHexString(await SHA256.HashDataAsync(file,token));
    if(!actual.Equals(sha,StringComparison.OrdinalIgnoreCase))throw new IOException("Download hash mismatch");return path;
   }
   string extractor=await Download("7zr.exe","https://github.com/ip7z/7zip/releases/download/24.09/7zr.exe","D2C0045523CF053A6B43F9315E9672FC2535F06AEADD4FFA53C729CD8B2B6DFE");
   string archiveTool=await Download("7z.exe","https://www.7-zip.org/a/7z2409-x64.exe","BDD1A33DE78618D16EE4CE148B849932C05D0015491C34887846D431D29F308E");
   string vpn=await Download("openconnect.exe","https://gitlab.com/api/v4/projects/openconnect%2Fopenconnect/jobs/artifacts/v9.21/raw/openconnect-installer-MinGW64-GnuTLS.exe?job=persist-windows-builds-for-tagged-releases","6EE9E8EB9BC59EF70BB0717DF7F99703F8A2CCD11D8E45D58A61F9A2E6EF7D00");
   string wintun=await Download("wintun.zip","https://www.wintun.net/builds/wintun-0.14.1.zip","07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51");
   async Task Extract(string executable,string archive,string destination){
    var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
    foreach(string arg in new[]{"x",archive,"-o"+destination,"-y"})info.ArgumentList.Add(arg);
    using var process=Process.Start(info)??throw new IOException("Cannot extract runtime");
    Task stdout=process.StandardOutput.ReadToEndAsync(),stderr=process.StandardError.ReadToEndAsync();
    using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromMinutes(2));
    try{await process.WaitForExitAsync(timeout.Token);}catch{try{process.Kill(true);}catch{}throw;}
    await Task.WhenAll(stdout,stderr);if(process.ExitCode!=0)throw new IOException("Cannot extract runtime");
   }
   progress("Распаковка VPN-компонентов…\nСоединение с VPN не выполняется.");
   string tools=Path.Combine(temporary,"tools"),unpacked=Path.Combine(temporary,"vpn"),staged=Path.Combine(temporary,"runtime");
   await Extract(extractor,archiveTool,tools);await Extract(Path.Combine(tools,"7z.exe"),vpn,unpacked);
   Directory.CreateDirectory(staged);
   foreach(string file in Directory.GetFiles(unpacked))if(Path.GetExtension(file).Equals(".dll",StringComparison.OrdinalIgnoreCase)||Path.GetFileName(file)=="openconnect.exe")File.Copy(file,Path.Combine(staged,Path.GetFileName(file)));
   using(var zip=ZipFile.OpenRead(wintun)){
    (zip.GetEntry("wintun/bin/amd64/wintun.dll")??throw new IOException("Missing Wintun")).ExtractToFile(Path.Combine(staged,"wintun.dll"),true);
    (zip.GetEntry("wintun/LICENSE.txt")??throw new IOException("Missing Wintun license")).ExtractToFile(Path.Combine(staged,"WINTUN-LICENSE.txt"));
   }
   foreach(string name in new[]{"openconnect.exe","libopenconnect-5.dll","libgnutls-30.dll","wintun.dll"})if(!File.Exists(Path.Combine(staged,name)))throw new IOException("Incomplete runtime");
   token.ThrowIfCancellationRequested();
   string backup=Path.Combine(temporary,"previous-client");
   if(Directory.Exists(client))Directory.Move(client,backup);
   try{Directory.Move(staged,client);}catch{if(Directory.Exists(backup))Directory.Move(backup,client);throw;}
  }finally{try{Directory.Delete(temporary,true);}catch{}}
 }
}
