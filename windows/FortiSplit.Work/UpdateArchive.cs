using System.IO.Compression;

namespace FortiSplit.Work;

internal static class UpdateArchive
{
 private static readonly HashSet<string> RootFiles=new(StringComparer.OrdinalIgnoreCase){"Forti Split.exe","Network.ps1","network-hook.js","profile.example.json","SECURITY.md","THIRD-PARTY.md","ПРОЧИТАЙ МЕНЯ.txt","fortisplit-update-v1.json"};
 private static bool SafeName(string name)
 {
  if(name.Length==0||name.Length>240||name.StartsWith('/')||name.Contains('\\')||name.Contains(':'))return false;
  var parts=name.TrimEnd('/').Split('/');
  if(parts.Any(p=>p.Length==0||p is "." or ".."||p.EndsWith(' ')||p.EndsWith('.')||p.Any(char.IsControl)))return false;
  return parts.Length==1?RootFiles.Contains(parts[0])||parts[0].Equals("licenses",StringComparison.OrdinalIgnoreCase):
   parts.Length<=4&&parts[0].Equals("licenses",StringComparison.OrdinalIgnoreCase)&&parts.Skip(1).All(p=>p.All(c=>char.IsAsciiLetterOrDigit(c)||c is '.' or '-' or '_'));
 }

 internal static void Extract(string archive,string destination)
 {
  if(Directory.Exists(destination)||File.Exists(destination))throw new IOException("Папка обновления уже существует.");
  Directory.CreateDirectory(destination);
  var found=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long total=0;int count=0;
  using var zip=ZipFile.OpenRead(archive);
  foreach(var entry in zip.Entries){
   if(++count>256||!SafeName(entry.FullName))throw new IOException("Некорректный архив обновления.");
   int unixType=(entry.ExternalAttributes>>16)&0xF000;
   if(unixType==0xA000||(entry.ExternalAttributes&0x400)!=0)throw new IOException("Ссылки в архиве не поддерживаются.");
   string normalized=entry.FullName.TrimEnd('/');
   if(!found.Add(normalized))throw new IOException("Повторный файл в архиве.");
   bool dir=entry.FullName.EndsWith('/');
   if(dir){if(!normalized.Equals("licenses",StringComparison.OrdinalIgnoreCase)&&!normalized.StartsWith("licenses/",StringComparison.OrdinalIgnoreCase))throw new IOException("Неверная папка в архиве.");continue;}
   long maxEntry=normalized.Equals("Forti Split.exe",StringComparison.OrdinalIgnoreCase)?160L*1024*1024:normalized.Equals("fortisplit-update-v1.json",StringComparison.OrdinalIgnoreCase)?4096:2L*1024*1024;
   if(entry.Length<0||entry.Length>maxEntry||total+entry.Length>256L*1024*1024)throw new IOException("Архив обновления слишком большой.");
   total+=entry.Length;
   string target=Path.GetFullPath(Path.Combine(destination,normalized.Replace('/',Path.DirectorySeparatorChar)));
   if(!target.StartsWith(Path.GetFullPath(destination)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("Неверный путь в архиве.");
   Directory.CreateDirectory(Path.GetDirectoryName(target)!);
   using var source=entry.Open();using var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None);
   byte[] buffer=new byte[81920];long copied=0;int n;
   while((n=source.Read(buffer,0,buffer.Length))>0){copied+=n;if(copied>entry.Length)throw new IOException("Неверный размер файла в архиве.");output.Write(buffer,0,n);}
   if(copied!=entry.Length)throw new IOException("Неполный файл в архиве.");
  }
  foreach(var name in new[]{"Forti Split.exe","Network.ps1","network-hook.js","fortisplit-update-v1.json"})if(!found.Contains(name))throw new IOException("В обновлении отсутствуют нужные файлы.");
  if(!found.Any(x=>x.StartsWith("licenses/",StringComparison.OrdinalIgnoreCase)))throw new IOException("В обновлении отсутствуют лицензии.");
  using(var marker=System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(Path.Combine(destination,"fortisplit-update-v1.json")))){
   if(marker.RootElement.GetProperty("format").GetInt32()!=1||!marker.RootElement.GetProperty("ready_signal").GetBoolean())throw new IOException("Этот выпуск не поддерживает автоматическое обновление.");
  }
  using var exe=new BinaryReader(File.OpenRead(Path.Combine(destination,"Forti Split.exe")));
  if(exe.BaseStream.Length<64||exe.ReadUInt16()!=0x5A4D)throw new IOException("Неверный файл приложения.");
  exe.BaseStream.Position=60;uint pe=exe.ReadUInt32();
  if(pe>exe.BaseStream.Length-6)throw new IOException("Неверный файл приложения.");
  exe.BaseStream.Position=pe;if(exe.ReadUInt32()!=0x4550||exe.ReadUInt16()!=0x8664)throw new IOException("Нужна версия Windows x64.");
 }
}
