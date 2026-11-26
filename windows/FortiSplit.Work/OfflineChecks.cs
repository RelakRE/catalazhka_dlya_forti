using System.IO.Pipes;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace FortiSplit.Work;

internal static class OfflineChecks
{
 internal static async Task<int> Run(string output)
 {
  var checks=new Dictionary<string,bool>();
  var failures=new Dictionary<string,OfflineFailure>();
  void RecordFailure(string check,string stage,Exception error){
   checks[check]=false;
   failures[check]=new(stage,error.GetType().Name,error is Win32Exception native?native.NativeErrorCode:error.HResult);
  }
  string nativeStage="native_library_abi";
  try{checks[nativeStage]=NativeAuth.ValidateAbi().Length>0;nativeStage="native_fortinet_init_without_network";checks[nativeStage]=NativeAuth.CheckInitialization();}
  catch(Exception error){RecordFailure(nativeStage,nativeStage,error);}
  using(var main=new MainForm(true)){
   main.Show();Application.DoEvents();
   var work=main.Controls.Find("work",true).OfType<TabPage>().Single();
   var settings=main.Controls.Find("settings",true).OfType<TabPage>().Single();
   checks["vpn_traffic_hidden_when_disconnected"]=!work.Controls.Find("vpn-traffic",true).Single().Visible;
   checks["main_has_one_connection_action"]=work.Controls.Find("connection-action",true).OfType<Button>().Count(button=>button.Visible)==1;
   checks["work_diagnostics_hidden_when_disconnected"]=!work.Controls.Find("check-work-address",true).OfType<Button>().Single().Visible;
   main.CheckPeerTrafficView(checks);
   main.CheckFailedWorkerStart(checks);
   checks["other_actions_on_settings"]=settings.Controls.Find("connection-action",true).Length==0 && settings.Controls.Find("settings-navigation",true).Length==1;
   checks["window_width_fixed"]=main.MinimumSize.Width==main.MaximumSize.Width && main.MinimumSize.Width>0 && main.MaximumSize.Height>main.MinimumSize.Height;
   checks["window_content_visible"]=main.Height>=main.MinimumSize.Height && main.ClientSize.Height>=300 && work.ClientSize.Height>=200;
   main.ShowSettings();Application.DoEvents();
   FlowLayoutPanel Page(string name)=>settings.Controls.Find("settings-page-"+name,true).OfType<FlowLayoutPanel>().Single();
   void Select(string name){settings.Controls.Find("settings-nav-"+name,true).OfType<RadioButton>().Single().Checked=true;Application.DoEvents();}
   checks["settings_opens_on_vpn_section"]=Page("vpn").Visible && !Page("addresses").Visible && !Page("apps").Visible && !Page("maintenance").Visible;
   var server=settings.Controls.Find("vpn-server",true).OfType<TextBox>().Single();
   server.Text="https://vpn.example.com";
   Select("apps");
   var picker=settings.Controls.Find("rdp-picker",true).OfType<TableLayoutPanel>().Single();
   checks["rdp_path_editable_with_browse"]=picker.Visible && picker.ColumnCount==2 && picker.Controls.OfType<TextBox>().Any(x=>!x.ReadOnly) && picker.Controls.OfType<Button>().Any(x=>x.Text=="Выбрать…" && x.AccessibleName=="Выбрать файл RDP");
   var appCard=picker.Parent!;
   checks["rdp_picker_fills_settings"]=Math.Abs(picker.Width-(appCard.ClientSize.Width-appCard.Padding.Horizontal))<=2;
   checks["rdp_picker_has_visible_controls"]=picker.Controls.OfType<TextBox>().Single().Width>100 && picker.Controls.OfType<Button>().Single().Right<=picker.ClientSize.Width;
   Select("vpn");
   checks["settings_switching_sections_keeps_pending_edits"]=server.Visible && server.Text=="https://vpn.example.com";
   Select("maintenance");
   var profiles=settings.Controls.Find("profile-actions",true).OfType<TableLayoutPanel>().Single();
   checks["profile_actions_share_row"]=profiles.Visible && profiles.ColumnCount==2 && profiles.Controls.OfType<Button>().Count()==2 && profiles.GetRow(profiles.Controls[0])==profiles.GetRow(profiles.Controls[1]);
   var viewport=settings.Controls.Find("settings-viewport",true).Single();
   var save=settings.Controls.Find("save-settings",true).OfType<Button>().Single();
   var notice=settings.Controls.Find("save-notice",true).OfType<Label>().Single();
   checks["save_fixed_and_visible"]=save.Visible && save.Parent?.Name=="settings-footer" && save.Bounds.Bottom<=save.Parent.ClientSize.Height;
   checks["save_notice_always_visible"]=notice.Parent==save.Parent && notice.Visible && notice.Right<=save.Left;
   checks["settings_and_footer_do_not_overlap"]=viewport.Bottom<=save.Parent!.Top;
   int defaultHeight=main.Height;
   main.Height=main.MinimumSize.Height;
   Page("maintenance").AutoScrollPosition=new Point(0,10000);Application.DoEvents();
   var updateActions=settings.Controls.Find("update-actions",true).OfType<TableLayoutPanel>().Single();
   var updateBounds=Page("maintenance").RectangleToClient(updateActions.RectangleToScreen(updateActions.ClientRectangle));
   checks["update_buttons_visible_at_scroll_end"]=updateBounds.Top>=0 && updateBounds.Bottom<=Page("maintenance").ClientSize.Height && updateActions.Controls.OfType<Button>().All(b=>b.Bottom<=updateActions.ClientSize.Height);
   checks["save_visible_when_scrolling"]=save.Visible && save.Bounds.Bottom<=save.Parent.ClientSize.Height;
   main.Height=defaultHeight;
   main.ShowWorkSites();Application.DoEvents();
   checks["work_addresses_shortcut_opens_only_addresses_section"]=Page("addresses").Visible && !Page("vpn").Visible && !Page("apps").Visible && !Page("maintenance").Visible;
   var addressInput=settings.Controls.Find("work-address-input",true).OfType<TextBox>().Single();
   var addressList=settings.Controls.Find("work-addresses",true).OfType<ListBox>().Single();
   var addAddress=settings.Controls.Find("add-work-address",true).OfType<Button>().Single();
   var removeAddress=settings.Controls.Find("remove-work-address",true).OfType<Button>().Single();
   var checkAddress=settings.Controls.Find("check-selected-work-address",true).OfType<Button>().Single();
   addressInput.Text="https://desktop.example.com/path";addAddress.PerformClick();
   addressInput.Text="192.0.2.20";addAddress.PerformClick();
   addressInput.Text="192.0.2.20";addAddress.PerformClick();
   checks["work_addresses_added_individually_without_duplicates"]=addressList.Items.Cast<string>().SequenceEqual(new[]{"desktop.example.com","192.0.2.20"});
   checks["selected_work_address_check_requires_vpn"]=addressList.SelectedIndex==1&&!checkAddress.Enabled;
   removeAddress.PerformClick();
   checks["selected_work_address_removed_individually"]=addressList.Items.Cast<string>().SequenceEqual(new[]{"desktop.example.com"});
   main.CheckConnectedSettings(checks);
  }
  OfflineWorkChecks.CheckDiagnosticCancellation(checks);
  string user=Guid.NewGuid().ToString("N"),secret=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
  const string vaultServer="https://credential-check.invalid";
  string vaultStage="save",vaultCheck="windows_vault_roundtrip";
  bool vaultEntrySaved=false;
  try{
   PasswordVault.Save(vaultServer,user,secret);vaultEntrySaved=true;
   vaultStage="load";checks[vaultCheck]=PasswordVault.Load(vaultServer,user)==secret;
   vaultCheck="windows_vault_delete";vaultStage="delete";PasswordVault.Remove(vaultServer,user);
   vaultStage="verify_deleted";checks[vaultCheck]=PasswordVault.Load(vaultServer,user)==null;
  }catch(Exception error){RecordFailure(vaultCheck,vaultStage,error);}
  finally{if(vaultEntrySaved)try{PasswordVault.Remove(vaultServer,user);}catch(Exception error){RecordFailure("windows_vault_cleanup","delete_test_entry",error);}}
  string pipeStage="create_server";
  try{
   // The STA stays available for the next WinForms checks; the pipe has no UI dependencies.
   checks["private_pipe_pid_and_reply"]=Task.Run(async ()=>{
    string name="FortiSplitOffline-"+Guid.NewGuid().ToString("N");
    using var server=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
    pipeStage="create_client";
     using var client=AuthPipe.OpenClient(name);
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    pipeStage="connect";
    await Task.WhenAll(server.WaitForConnectionAsync(timeout.Token),client.ConnectAsync(timeout.Token));
    pipeStage="verify_client_pid";AuthPipe.VerifyClient(server,Environment.ProcessId);
    pipeStage="verify_server_pid";AuthPipe.VerifyServer(client,Environment.ProcessId);
    var sent=new AuthReply(false,new(){{"password",secret}});
    pipeStage="exchange";
    Task write=AuthPipe.Write(client,sent,timeout.Token);AuthReply received=await AuthPipe.Read<AuthReply>(server,timeout.Token);await write;
    return received.Values["password"]==secret;
   }).GetAwaiter().GetResult();
  }catch(Exception error){RecordFailure("private_pipe_pid_and_reply",pipeStage,error);}
  using(var dialog=new AuthDialog(new("form","Login","",[new("username","User",1,[]),new("password","Password",2,[])],"_login"),new Config{User="sample.user"},null)){
   checks["login_prefilled_in_native_form"]=dialog.Controls.Cast<Control>().SelectMany(c=>c.Controls.Cast<Control>()).OfType<TextBox>().Any(c=>c.Text=="sample.user");
  }
  var diagnosticNetwork=new WorkNetwork(Guid.Empty.ToString(),0,"192.0.2.20","ready",
   [new("desktop.example.com",["192.0.2.10"]),new("video.example.com",["192.0.2.11"])]);
  using(var diagnostic=new WorkConnectionDialog(diagnosticNetwork,()=>false,"video.example.com")){
   var address=diagnostic.Controls.Find("diagnostic-address",true).OfType<ComboBox>().Single();
   var mode=diagnostic.Controls.Find("diagnostic-mode",true).OfType<ComboBox>().Single();
   checks["work_diagnostics_preselects_only_the_chosen_address"]=address.Items.Count==1 && address.SelectedItem is WorkPeer{Address:"192.0.2.11"} && mode.Text=="Маршрут и пинг";
  }
  try{
   var route=await WorkConnectionCheck.Run(diagnosticNetwork,IPAddress.Loopback,3389,CancellationToken.None).ConfigureAwait(false);
   checks["work_diagnostics_reads_nonvpn_route_without_probing"]=route is { Route:"Вне VPN", Ping:null, Tcp:null };
  }catch(Exception error){RecordFailure("work_diagnostics_reads_nonvpn_route_without_probing","read_route",error);}
  string recoveryTest=Path.Combine(Path.GetTempPath(),"FortiSplitRecoveryCheck-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(recoveryTest);
  try{
   using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
   var otherSid=new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.NullSid,null);
   checks["worker_checks_parent_user_sid"]=Worker.ProcessUsesAccount(Environment.ProcessId,identity.User!) &&
    !Worker.ProcessUsesAccount(Environment.ProcessId,otherSid);
   bool elevated=new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
   string scriptRoot=Path.Combine(recoveryTest,"hooks");
   if(elevated){
    NetworkScripts.InstallInto(scriptRoot);
    NetworkScripts.InstallInto(scriptRoot);
    checks["protected_script_install_is_repeatable"]=true;
    string outputDirectory=Path.Combine(scriptRoot,"session-output");
    NetworkScripts.EnsureDirectory(outputDirectory,identity.User);
    NetworkScripts.EnsureDirectory(outputDirectory,identity.User);
    string statusFile=Path.Combine(outputDirectory,"status.json");
    Storage.Save(statusFile,new{Stage="offline"});
    var rules=new FileInfo(statusFile).GetAccessControl().GetAccessRules(true,true,typeof(SecurityIdentifier))
     .Cast<FileSystemAccessRule>().Where(rule=>rule.IdentityReference.Equals(identity.User)).ToArray();
    checks["session_output_is_read_only_for_the_desktop"]=rules.Length==1&&
     (rules[0].FileSystemRights&FileSystemRights.Read)==FileSystemRights.Read&&
     (rules[0].FileSystemRights&(FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions))==0;
   }
   foreach(string name in new[]{"Network.ps1","network-hook.js","NetworkGuard.cs"}){
    using var embedded=typeof(NetworkScripts).Assembly.GetManifestResourceStream(name);
    if(!elevated&&name=="NetworkGuard.cs"){
     checks["embedded_"+name]=embedded is {Length:>0};
     continue;
    }
    string path=elevated?Directory.GetFiles(scriptRoot,name,SearchOption.AllDirectories).Single():Path.Combine(AppContext.BaseDirectory,name);
    using var file=File.OpenRead(path);
    checks["embedded_"+name]=embedded is not null && SHA256.HashData(embedded).SequenceEqual(SHA256.HashData(file));
   }
   string image=Path.Combine(recoveryTest,"openconnect.exe");
   string savedProcess=Path.Combine(recoveryTest,"vpn-process.json");
   Storage.Save(savedProcess,new{Id=Environment.ProcessId,StartTicks=0L,Image=image});
   try{Worker.StopSavedClient(savedProcess);checks["manual_recovery_refuses_own_process"]=false;}catch(IOException){checks["manual_recovery_refuses_own_process"]=true;}
   Storage.Save(savedProcess,new{Id=int.MaxValue,StartTicks=0L,Image=image});
   Worker.StopSavedClient(savedProcess);checks["manual_recovery_handles_missing_process"]=true;
   Storage.Save(savedProcess,new{Id=int.MaxValue,StartTicks=1L,Image=image});
   checks["legacy_recovery_recognizes_exited_process"]=Worker.LegacyClientExited(savedProcess);
   using(var ownProcess=Process.GetCurrentProcess()){
    Storage.Save(savedProcess,new{Id=ownProcess.Id,StartTicks=ownProcess.StartTime.ToUniversalTime().Ticks,Image=image});
    checks["legacy_recovery_reports_live_process_without_stopping_it"]=!Worker.LegacyClientExited(savedProcess);
   }
   string lockPath=Path.Combine(recoveryTest,"session.lock");
   using(var firstLock=NetworkScripts.AcquireLock(lockPath,TimeSpan.Zero))
   using(var blockedLock=NetworkScripts.AcquireLock(lockPath,TimeSpan.Zero))
    checks["session_file_lock_is_exclusive"]=firstLock is not null&&blockedLock is null;
   using(var reopenedLock=NetworkScripts.AcquireLock(lockPath,TimeSpan.Zero))
    checks["session_file_lock_can_be_reopened"]=reopenedLock is not null;
   string journal=Path.Combine(recoveryTest,"journals");
   Directory.CreateDirectory(journal);
   string orphanId=Guid.NewGuid().ToString("N"),sid=identity.User!.Value;
   File.WriteAllText(Path.Combine(journal,sid+"-"+orphanId+".json"),"{}");
   string processJournal=Path.Combine(journal,sid+"-"+orphanId+".vpn.json");
   Storage.Save(processJournal,new{Id=Environment.ProcessId,StartTicks=0L,Image=image});
   string otherId=Guid.NewGuid().ToString("N");
   File.WriteAllText(Path.Combine(journal,otherSid.Value+"-"+otherId+".json"),"{}");
   File.WriteAllText(Path.Combine(journal,"S-invalid-"+Guid.NewGuid().ToString("N")+".json"),"{}");
   var pending=NetworkScripts.PendingSessions(journal).ToHashSet();
   checks["recovery_discovers_protected_orphans_across_accounts"]=pending.SetEquals(new[]{(sid,orphanId),(otherSid.Value,otherId)})
    && !Directory.Exists(Path.Combine(recoveryTest,orphanId));
   try{Worker.StopSavedClient(processJournal);checks["orphan_recovery_reads_protected_process_identity"]=false;}
   catch(IOException){checks["orphan_recovery_reads_protected_process_identity"]=true;}
  }catch(Exception error){RecordFailure("manual_recovery_handles_missing_process","verify_recovery",error);}
  finally{try{Directory.Delete(recoveryTest,true);}catch{}}
  string signatureTest=Path.Combine(Path.GetTempPath(),"FortiSplitSignatureCheck-"+Guid.NewGuid().ToString("N"));
  try{checks["update_rejects_executable_different_from_signed_archive"]=OfflineUpdateChecks.RejectsDifferentExecutable(signatureTest);}
  catch(Exception error){RecordFailure("update_rejects_executable_different_from_signed_archive","verify_update",error);}
  finally{try{Directory.Delete(signatureTest,true);}catch{}}
  foreach(bool previous in new[]{false,true}){
   string check=previous?"update_failure_restores_previous_link_and_profile":"update_failure_restores_original_and_profile";
   string directory=Path.Combine(Path.GetTempPath(),"FortiSplitUpdateCheck-"+Guid.NewGuid().ToString("N"));
   try{checks[check]=OfflineUpdateChecks.FailedLaunchRestoresPrevious(directory,previous);}
   catch(Exception error){RecordFailure(check,"simulate_failed_launch",error);}
   finally{try{Directory.Delete(directory,true);}catch{}}
  }
  bool passed=checks.Values.All(x=>x);Storage.Save(Path.GetFullPath(output),new{Successful=passed,Checks=checks,Failures=failures,NoVpnConnection=true});return passed?0:1;
 }

 private sealed record OfflineFailure(string Stage,string ErrorType,int Code);
}

internal sealed partial class MainForm
{
 internal void CheckFailedWorkerStart(Dictionary<string,bool> checks)
 {
  // A failed Process.Start follows the same rollback path as a refused UAC launch.
  using var previous=Process.GetCurrentProcess();
  string missing=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"),"absent.exe");
  worker=previous;folder="previous-session";
  try {
   StartWorker(new ProcessStartInfo(missing){UseShellExecute=false},"new-session");
   checks["failed_start_preserves_previous_worker"]=false;
  }catch(Win32Exception){
   checks["failed_start_preserves_previous_worker"]=worker.Id==Environment.ProcessId && folder=="previous-session";
  }finally{worker=null;folder=null;}
  status=new("recovery_required","");stopRequested=true;RefreshUi();
  bool blocked=!connect.Enabled;
  status=new("disconnected","",Restored:true);CompleteWorker(0);RefreshUi();
  checks["empty_recovery_enables_connect"]=blocked && connect.Enabled && status.Restored && status.Stage=="disconnected";
  status=new("preparing","");stopRequested=false;
  CompleteWorker(Worker.AccountMismatchExitCode);RefreshUi();
  checks["different_admin_account_reports_connection_error"]=connect.Enabled && status.Stage=="error" &&
   status.Message==Worker.AccountMismatchMessage;
  recovering=true;status=new("disconnecting","");
  CompleteWorker(Worker.AccountMismatchExitCode);RefreshUi();
  checks["different_admin_account_keeps_recovery_required"]=!connect.Enabled && status.Stage=="recovery_required";
 }
}
