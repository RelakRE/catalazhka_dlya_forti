using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FortiSplit.Work;

internal static class PasswordVault
{
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Credential {
  public uint Flags,Type; public string TargetName; public string? Comment;
  public long LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob;
  public uint Persist,AttributeCount; public IntPtr Attributes; public string? TargetAlias,UserName;
 }
 [DllImport("advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool Write(ref Credential credential,uint flags);
 [DllImport("advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool Read(string target,uint type,uint flags,out IntPtr credential);
 [DllImport("advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool Delete(string target,uint type,uint flags);
 [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr credential);
 private static string Key(string server,string user) => "FortiSplit/"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(new Uri(server).GetLeftPart(UriPartial.Path).TrimEnd('/')+"\n"+user)));
 internal static void Save(string server,string user,string password) {
  byte[] bytes=Encoding.Unicode.GetBytes(password);if(bytes.Length>5120)throw new ArgumentException("Пароль слишком длинный.");
  IntPtr blob=Marshal.AllocHGlobal(bytes.Length);
  try {Marshal.Copy(bytes,0,blob,bytes.Length);var credential=new Credential{Type=1,TargetName=Key(server,user),UserName=user,CredentialBlob=blob,CredentialBlobSize=(uint)bytes.Length,Persist=2};if(!Write(ref credential,0))throw new Win32Exception(Marshal.GetLastWin32Error());}
  finally{for(int i=0;i<bytes.Length;i++)Marshal.WriteByte(blob,i,0);Marshal.FreeHGlobal(blob);CryptographicOperations.ZeroMemory(bytes);}
 }
 internal static string? Load(string server,string user) {
  if(!Read(Key(server,user),1,0,out var pointer)){int error=Marshal.GetLastWin32Error();if(error==1168)return null;throw new Win32Exception(error);}
  try {var credential=Marshal.PtrToStructure<Credential>(pointer);return Marshal.PtrToStringUni(credential.CredentialBlob,checked((int)credential.CredentialBlobSize/2));}finally{CredFree(pointer);}
 }
 internal static void Remove(string server,string user) {if(!Delete(Key(server,user),1,0)&&Marshal.GetLastWin32Error()!=1168)throw new Win32Exception(Marshal.GetLastWin32Error());}
}
