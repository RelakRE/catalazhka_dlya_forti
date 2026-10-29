using System.IO.Pipes;

namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 internal void ShowSettings()=>tabs.SelectedIndex=1;
 private readonly CheckBox rememberPassword=Check("Сохранять пароль");
 private NamedPipeServerStream? authServer;
 private CancellationTokenSource? authStop;
 private AuthDialog? authDialog;
 private void BeginAuth(string id){CancelAuth();authStop=new();authServer=new NamedPipeServerStream(AuthPipe.Name(id),PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);}
 private void CancelAuth(){authStop?.Cancel();authServer?.Dispose();authDialog?.Close();authServer=null;}
 private void SaveProfile(Config config)
 {
  config.Validate();
  string path=Path.Combine(Storage.Root,"settings.json");
  if(File.Exists(path)){
   Config old=Storage.Read<Config>(path);
   if(old.RememberPassword&&(!config.RememberPassword||old.User!=config.User||old.Server!=config.Server))PasswordVault.Remove(old.Server,old.User);
  }
  if(!config.RememberPassword)PasswordVault.Remove(config.Server,config.User);
  Storage.Save(path,config);profile=config;
 }
 private async Task ServeAuth(int workerPid,Config config)
 {
  var server=authServer;var cancellation=authStop;if(server is null||cancellation is null)return;
  string? pendingPassword=null;
  try{
   await server.WaitForConnectionAsync(cancellation.Token);AuthPipe.VerifyClient(server,workerPid);
   while(true){
    AuthRequest request=await AuthPipe.Read<AuthRequest>(server,cancellation.Token);
    if(request.Kind=="authenticated"){
     if(pendingPassword is not null&&config.RememberPassword){try{PasswordVault.Save(config.Server,config.User,pendingPassword);}catch(Exception){MessageBox.Show("Вход выполнен, но Windows не разрешила сохранить пароль.",Text);}}
     await AuthPipe.Write(server,new AuthReply(false,[]),cancellation.Token);break;
    }
    if(request.Kind!="form"||request.Fields.Length>32)throw new IOException("Неверная форма входа.");
    string? saved=request.Attempt==1&&config.RememberPassword&&request.Fields.Any(f=>AuthPolicy.IsPassword(f,request))?PasswordVault.Load(config.Server,config.User):null;
    using(var dialog=new AuthDialog(request,config,saved)){
     saved=null;authDialog=dialog;dialog.ShowDialog(this);authDialog=null;
     AuthReply reply=dialog.Reply();
     if(!reply.Cancelled){
      foreach(var field in request.Fields){
       if(AuthPolicy.IsUser(field)){config.User=reply.Values[field.Name].Trim();user.Text=config.User;}
       if(AuthPolicy.IsPassword(field,request)){config.RememberPassword=dialog.Remember.Checked;rememberPassword.Checked=config.RememberPassword;pendingPassword=config.RememberPassword?reply.Values[field.Name]:null;}
      }
      // Only the non-secret login/preferences reach JSON. Password waits for auth success.
      SaveProfile(config);
     }
     await AuthPipe.Write(server,reply,cancellation.Token);
     if(reply.Cancelled)break;
    }
   }
  }catch(OperationCanceledException){}catch(IOException){}catch(ObjectDisposedException){}
  catch(Exception){detail.Text="Не удалось обработать вход. Подключитесь повторно после проверки настроек.";stop?.Set();}
  finally{pendingPassword=null;server.Dispose();if(ReferenceEquals(authServer,server))authServer=null;if(ReferenceEquals(authStop,cancellation))authStop=null;cancellation.Dispose();}
 }
}
