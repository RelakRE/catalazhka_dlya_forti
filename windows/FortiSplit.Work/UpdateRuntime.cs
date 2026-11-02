namespace FortiSplit.Work;

internal static class UpdateRuntime
{
 internal static void Copy(string source,string destination)
 {
  if(!Directory.Exists(source)||Directory.Exists(destination))throw new IOException("VPN-компоненты недоступны для переноса.");
  if((File.GetAttributes(source)&FileAttributes.ReparsePoint)!=0)throw new IOException("Ссылка на VPN-компоненты не поддерживается.");
  Directory.CreateDirectory(destination);long total=0;int count=0;
  foreach(string file in Directory.EnumerateFiles(source)){
   var info=new FileInfo(file);
   if((info.Attributes&FileAttributes.ReparsePoint)!=0||++count>256||info.Length>160L*1024*1024||(total+=info.Length)>512L*1024*1024)throw new IOException("Не удалось перенести VPN-компоненты.");
   using var input=info.OpenRead();using var output=new FileStream(Path.Combine(destination,info.Name),FileMode.CreateNew,FileAccess.Write,FileShare.None);input.CopyTo(output);
  }
  foreach(string name in new[]{"openconnect.exe","libopenconnect-5.dll","libgnutls-30.dll","wintun.dll"}){
   var file=new FileInfo(Path.Combine(destination,name));if(!file.Exists||file.Length==0)throw new IOException("VPN-компоненты неполные.");
  }
 }
}
