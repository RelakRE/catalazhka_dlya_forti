using System.IO.Pipes;
using System.Security.Cryptography;

namespace FortiSplit.Work;

internal static class OfflineChecks
{
 internal static async Task<int> Run(string output)
 {
  var checks=new Dictionary<string,bool>();
  try{checks["native_library_abi"]=NativeAuth.ValidateAbi().Length>0;checks["native_fortinet_init_without_network"]=NativeAuth.CheckInitialization();}catch(Exception){checks["native_library_abi"]=false;}
  string user=Guid.NewGuid().ToString("N"),secret=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
  try{PasswordVault.Save("https://credential-check.invalid",user,secret);checks["windows_vault_roundtrip"]=PasswordVault.Load("https://credential-check.invalid",user)==secret;PasswordVault.Remove("https://credential-check.invalid",user);checks["windows_vault_delete"]=PasswordVault.Load("https://credential-check.invalid",user)==null;}
  catch(Exception){checks["windows_vault_roundtrip"]=false;}finally{try{PasswordVault.Remove("https://credential-check.invalid",user);}catch(Exception){}}
  try{
   string name="FortiSplitOffline-"+Guid.NewGuid().ToString("N");
   using var server=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
   using var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous);
   using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
   await Task.WhenAll(server.WaitForConnectionAsync(timeout.Token),client.ConnectAsync(timeout.Token));
   AuthPipe.VerifyClient(server,Environment.ProcessId);AuthPipe.VerifyServer(client,Environment.ProcessId);
   var sent=new AuthReply(false,new(){{"password",secret}});
   Task write=AuthPipe.Write(client,sent,timeout.Token);AuthReply received=await AuthPipe.Read<AuthReply>(server,timeout.Token);await write;
   checks["private_pipe_pid_and_reply"]=received.Values["password"]==secret;
  }catch(Exception){checks["private_pipe_pid_and_reply"]=false;}
  using(var dialog=new AuthDialog(new("form","Login","",[new("username","User",1,[]),new("password","Password",2,[])],"_login"),new Config{User="sample.user"},null)){
   checks["login_prefilled_in_native_form"]=dialog.Controls.Cast<Control>().SelectMany(c=>c.Controls.Cast<Control>()).OfType<TextBox>().Any(c=>c.Text=="sample.user");
  }
  bool passed=checks.Values.All(x=>x);Storage.Save(Path.GetFullPath(output),new{Successful=passed,Checks=checks,NoVpnConnection=true});return passed?0:1;
 }
}
