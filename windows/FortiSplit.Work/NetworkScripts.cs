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
 internal static bool HasJournal(string id) {
  using var identity = WindowsIdentity.GetCurrent();
  return File.Exists(Path.Combine(Root, "state", identity.User!.Value + "-" + id + ".json"));
 }

 // Called by the elevated worker under the machine-wide session mutex.
 internal static void Prepare() => InstallInto(Root);

 internal static void InstallInto(string directory)
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
   throw new IOException("Проверьте права доступа к системной папке сетевого обработчика.");

  string versionDirectory = Path.Combine(directory, BuildId);
  Storage.RegularPath(versionDirectory);
  Directory.CreateDirectory(versionDirectory);
  string stateDirectory = Path.Combine(directory, "state");
  Storage.RegularPath(stateDirectory);
  Directory.CreateDirectory(stateDirectory);
  foreach (string name in new[] { "network-hook.js", "Network.ps1" }) {
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
}
