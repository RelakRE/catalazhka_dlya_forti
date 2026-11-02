using System.IO.Pipes;
using System.Security.Cryptography;

namespace FortiSplit.Work;

internal static class OfflineChecks
{
 internal static async Task<int> Run(string output)
 {
  var checks=new Dictionary<string,bool>();
  try{checks["native_library_abi"]=NativeAuth.ValidateAbi().Length>0;checks["native_fortinet_init_without_network"]=NativeAuth.CheckInitialization();}catch(Exception){checks["native_library_abi"]=false;}
  using(var main=new MainForm(true)){
   main.Show();Application.DoEvents();
   var work=main.Controls.Find("work",true).OfType<TabPage>().Single();
   var settings=main.Controls.Find("settings",true).OfType<TabPage>().Single();
   checks["main_has_one_connection_action"]=work.Controls.Find("connection-action",true).OfType<Button>().Count()==1 && work.Controls.Find("work-content",true).OfType<FlowLayoutPanel>().Single().Controls.OfType<Button>().Count()==1;
   checks["other_actions_on_settings"]=settings.Controls.Find("connection-action",true).Length==0 && settings.Controls.OfType<FlowLayoutPanel>().Any();
   checks["window_width_fixed"]=main.MinimumSize.Width==main.MaximumSize.Width && main.MinimumSize.Width>0 && main.MaximumSize.Height>main.MinimumSize.Height;
   checks["window_content_visible"]=main.Height>=main.MinimumSize.Height && main.ClientSize.Height>=300 && work.ClientSize.Height>=200;
   main.ShowSettings();Application.DoEvents();
   checks["settings_content_visible"]=settings.ClientSize.Height>=200 && settings.Controls.OfType<FlowLayoutPanel>().Any(c=>c.ClientSize.Height>=200);
   var picker=settings.Controls.Find("rdp-picker",true).OfType<TableLayoutPanel>().Single();
   checks["rdp_path_editable_with_browse"]=picker.ColumnCount==2 && picker.Controls.OfType<TextBox>().Any(x=>!x.ReadOnly) && picker.Controls.OfType<Button>().Any(x=>x.Text=="\uE8B7" && x.AccessibleName=="Выбрать файл RDP");
   var profiles=settings.Controls.Find("profile-actions",true).OfType<TableLayoutPanel>().Single();
   checks["profile_actions_share_row"]=profiles.ColumnCount==2 && profiles.Controls.OfType<Button>().Count()==2 && profiles.GetRow(profiles.Controls[0])==profiles.GetRow(profiles.Controls[1]);
   var config=settings.Controls.Find("settings-content",true).OfType<FlowLayoutPanel>().Single();
   var save=settings.Controls.Find("save-settings",true).OfType<Button>().Single();
   var notice=settings.Controls.Find("save-notice",true).OfType<Label>().Single();
   checks["save_fixed_and_visible"]=save.Visible && save.Parent?.Name=="settings-footer" && save.Bounds.Bottom<=save.Parent.ClientSize.Height;
   checks["save_notice_always_visible"]=notice.Parent==save.Parent && notice.Visible && notice.Bottom<=save.Top;
   checks["settings_and_footer_do_not_overlap"]=config.Bottom<=save.Parent!.Top;
   checks["rdp_picker_fills_settings"]=Math.Abs(picker.Width-(config.ClientSize.Width-config.Padding.Horizontal))<=2;
   checks["rdp_picker_has_visible_controls"]=picker.Controls.OfType<TextBox>().Single().Width>100 && picker.Controls.OfType<Button>().Single().Right<=picker.ClientSize.Width;
   checks["save_fills_footer"]=Math.Abs(save.Width-(save.Parent!.ClientSize.Width-save.Parent.Padding.Horizontal))<=2;
   config.AutoScrollPosition=new Point(0,10000);Application.DoEvents();
   var updateActions=settings.Controls.Find("update-actions",true).OfType<TableLayoutPanel>().Single();
   checks["update_buttons_visible_at_scroll_end"]=updateActions.Top>=0 && updateActions.Bottom<=config.ClientSize.Height && updateActions.Controls.OfType<Button>().All(b=>b.Bottom<=updateActions.ClientSize.Height);
   checks["save_visible_when_scrolling"]=save.Visible && save.Bounds.Bottom<=save.Parent.ClientSize.Height;
   settings.Controls.Find("advanced-toggle",true).OfType<CheckBox>().Single().Checked=true;Application.DoEvents();
   var advanced=settings.Controls.Find("advanced-content",true).OfType<FlowLayoutPanel>().Single();
   checks["advanced_fields_fit"]=advanced.Visible && advanced.Controls.Cast<Control>().Where(c=>c.Visible).All(c=>c.Bottom+c.Margin.Bottom<=advanced.ClientSize.Height);
   checks["advanced_fills_settings"]=Math.Abs(advanced.Width-(config.ClientSize.Width-config.Padding.Horizontal))<=2;
   checks["save_visible_with_advanced"]=save.Visible && config.Bottom<=save.Parent.Top;
  }
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
  string recoveryTest=Path.Combine(Path.GetTempPath(),"FortiSplitRecoveryCheck-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(recoveryTest);
  try{
   string image=Path.Combine(recoveryTest,"openconnect.exe");
   Storage.Save(Path.Combine(recoveryTest,"vpn-process.json"),new{Id=Environment.ProcessId,StartTicks=0L,Image=image});
   try{Worker.StopSavedClient(recoveryTest);checks["manual_recovery_refuses_own_process"]=false;}catch(IOException){checks["manual_recovery_refuses_own_process"]=true;}
   Storage.Save(Path.Combine(recoveryTest,"vpn-process.json"),new{Id=int.MaxValue,StartTicks=0L,Image=image});
   Worker.StopSavedClient(recoveryTest);checks["manual_recovery_handles_missing_process"]=true;
  }catch(Exception){checks["manual_recovery_handles_missing_process"]=false;}
  finally{try{Directory.Delete(recoveryTest,true);}catch{}}
  bool passed=checks.Values.All(x=>x);Storage.Save(Path.GetFullPath(output),new{Successful=passed,Checks=checks,NoVpnConnection=true});return passed?0:1;
 }
}
