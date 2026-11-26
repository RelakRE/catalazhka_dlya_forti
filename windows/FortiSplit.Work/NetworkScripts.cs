using System.Security.AccessControl;
using System.Security.Principal;

namespace FortiSplit.Work;

internal static class NetworkScripts
{
 private static readonly string Root = Path.Combine(
  Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Forti Split Network");
 private static readonly string BuildId = typeof(NetworkScripts).Module.ModuleVersionId.ToString("N");
 internal static string Hook => Path.Combine(Root, BuildId, "network-hook.js");
 internal static string PowerShellScript => Path.Combine(Root, BuildId, "Network.ps1");
 internal static string StateDirectory => Path.Combine(Root, "state");
 private static string WorkerDirectory => Path.Combine(Root, "workers", BuildId);
 internal static string WorkerExecutable => Path.Combine(WorkerDirectory, "FortiSplit.exe");
 internal static string RuntimeDirectory => Path.Combine(Root, RuntimeSetup.RuntimeVersion);
 internal static string ClientJournal(string sid,string id) => Path.Combine(StateDirectory,sid+"-"+id+".vpn.json");
 internal static string HookLease(string sid,string id) => Path.Combine(StateDirectory,sid+"-"+id+".live");
 internal static bool HasJournal(string sid,string id) => File.Exists(Path.Combine(StateDirectory,sid+"-"+id+".json"));

 internal static string SessionPath(string sid, string id)
 {
  if (!Guid.TryParseExact(id, "N", out var session) || new SecurityIdentifier(sid).Value != sid)
   throw new ArgumentException("Неверный сеанс.");
  return Path.Combine(Root, "sessions", sid + "-" + session.ToString("N"));
 }

 internal static void PrepareSession(string sid, string id)
 {
  string path = SessionPath(sid, id);
  EnsureDirectory(Root, null);
  EnsureDirectory(Path.GetDirectoryName(path)!, null);
  EnsureDirectory(path, new SecurityIdentifier(sid));
 }

 internal static IEnumerable<(string Sid, string Id)> PendingSessions(string directory)
 {
  foreach(string path in Directory.EnumerateFiles(directory,"S-*.json")){
   string name=Path.GetFileNameWithoutExtension(path);
   if(name.EndsWith(".vpn",StringComparison.OrdinalIgnoreCase))name=name[..^4];
   int separator = name.LastIndexOf('-');
   if(separator < 2 || !Guid.TryParseExact(name[(separator + 1)..],"N",out var session))continue;
   string sid = name[..separator];
   SecurityIdentifier owner;
   try { owner = new SecurityIdentifier(sid); }
   catch (ArgumentException) { continue; }
   if (owner.Value == sid) yield return (sid, session.ToString("N"));
  }
 }

 // Called by the elevated worker under the machine-wide session mutex.
 internal static void Prepare() => InstallInto(Root);

 internal static void InstallWorker(string source)
 {
  EnsureDirectory(Path.GetDirectoryName(WorkerDirectory)!, null);
  EnsureDirectory(WorkerDirectory, new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null));
  string target = WorkerExecutable;
  Storage.RegularPath(target);
  if (File.Exists(target)) return;
  string temporary = target + "." + Guid.NewGuid().ToString("N");
  try {
   using (var input = File.OpenRead(source))
   using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    input.CopyTo(output);
   File.Move(temporary, target);
  } finally { File.Delete(temporary); }
 }

 internal static void PrepareRuntimeDirectory() => EnsureDirectory(RuntimeDirectory, null);

 internal static void SetSystemEnvironment(System.Diagnostics.ProcessStartInfo process, string temporary)
 {
  string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
  string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
  process.Environment["PATH"] = system + Path.PathSeparator + windows;
  process.Environment["SystemRoot"] = windows;
  process.Environment["windir"] = windows;
  process.Environment["PSModulePath"] = Path.Combine(system, "WindowsPowerShell", "v1.0", "Modules");
  process.Environment["TEMP"] = process.Environment["TMP"] = temporary;
 }

 internal static void InstallInto(string directory)
 {
  EnsureDirectory(directory, null);
  string versionDirectory = Path.Combine(directory, BuildId);
  Storage.RegularPath(versionDirectory);
  Directory.CreateDirectory(versionDirectory);
  string stateDirectory = Path.Combine(directory, "state");
  Storage.RegularPath(stateDirectory);
  Directory.CreateDirectory(stateDirectory);
  foreach (string name in new[] { "network-hook.js", "Network.ps1", "NetworkGuard.cs" }) {
   string path = Path.Combine(versionDirectory, name);
   Storage.RegularPath(path);
   if (File.Exists(path)) continue;
   using var source = typeof(NetworkScripts).Assembly.GetManifestResourceStream(name)
    ?? throw new IOException("В приложении отсутствует сетевой обработчик.");
   string temporary = path + ".tmp";
   using (var output = File.Create(temporary)) source.CopyTo(output);
   File.Move(temporary, path);
  }
 }

 internal static void EnsureDirectory(string directory, SecurityIdentifier? reader)
 {
  var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
  var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
  var owner = new SecurityIdentifier(WellKnownSidType.WinCreatorOwnerRightsSid, null);
  const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
  var acl = new DirectorySecurity();
  acl.SetOwner(admins);
  acl.SetAccessRuleProtection(true, false);
  foreach (var sid in new[] { admins, system })
   acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit,
    PropagationFlags.None, AccessControlType.Allow));
  // Suppress implicit WRITE_DAC for a creator using their filtered user token.
  acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.ReadPermissions, inherit,
   PropagationFlags.None, AccessControlType.Allow));
  if (reader is not null)
   acl.AddAccessRule(new FileSystemAccessRule(reader, FileSystemRights.ReadAndExecute, inherit,
    PropagationFlags.None, AccessControlType.Allow));
  var root = new DirectoryInfo(directory);
  Storage.RegularPath(directory);
  root.Create(acl);
  const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
  var installed = root.GetAccessControl(sections);
  var rules = installed.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
  var required = acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
  if (!admins.Equals(installed.GetOwner(typeof(SecurityIdentifier))) || !installed.AreAccessRulesProtected ||
      rules.Length != required.Length || !required.All(expected => rules.Any(rule =>
       rule.IdentityReference.Equals(expected.IdentityReference) && rule.AccessControlType == expected.AccessControlType &&
       rule.FileSystemRights == expected.FileSystemRights && rule.InheritanceFlags == expected.InheritanceFlags &&
       rule.PropagationFlags == expected.PropagationFlags)))
   throw new IOException("Проверьте права доступа к системной папке Forti Split.");
 }
}
