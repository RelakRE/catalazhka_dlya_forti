using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace FortiSplit.Work;

internal static class Storage
{
 internal static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Forti Split Work");
 internal static string PowerShell => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\WindowsPowerShell\v1.0\powershell.exe");
 internal static void RegularPath(string path)
 {
  for (var dir = new DirectoryInfo(Path.GetFullPath(path)); dir != null; dir = dir.Parent)
   if (dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в пути не поддержаны.");
  if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылка вместо файла.");
 }
 internal static string SessionPath(string id)
 {
  if (!Guid.TryParseExact(id,"N", out _)) throw new ArgumentException("Неверный сеанс.");
  string path = Path.Combine(Root,"sessions",id); RegularPath(path); return path;
 }
 internal static void Save(string path, object value)
 {
  RegularPath(path); string tmp=path+".tmp"; RegularPath(tmp);
  File.WriteAllText(tmp,JsonSerializer.Serialize(value,Config.Json)); File.Move(tmp,path,true);
 }
 internal static T Read<T>(string path)
 {
  RegularPath(path); if (new FileInfo(path).Length > 1048576) throw new IOException("Слишком большой файл настроек.");
  return JsonSerializer.Deserialize<T>(File.ReadAllText(path),Config.Json) ?? throw new IOException("Пустые настройки.");
 }
 internal static void Protect(string folder)
 {
  RegularPath(folder); Directory.CreateDirectory(folder);
  using var identity=WindowsIdentity.GetCurrent();
  var acl=new DirectorySecurity(); acl.SetAccessRuleProtection(true,false);
  foreach (var sid in new[] {identity.User!,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)})
   acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  new DirectoryInfo(folder).SetAccessControl(acl);
 }
}
