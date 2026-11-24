using System.Diagnostics;

namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private readonly Label updateBanner=new(){AutoSize=true,Visible=false,ForeColor=SystemColors.HotTrack,Margin=new Padding(0,8,0,4)};
 private readonly Label updateInfo=new(){Text="Проверка при запуске приложения.",AutoSize=true,ForeColor=WorkMuted,Margin=new Padding(0,3,0,8)};
 private readonly Button installUpdate=Btn("Обновить"),openUpdate=Btn("Открыть выпуск");
 private readonly CancellationTokenSource updateStop=new();
 private UpdateCandidate? availableUpdate;
 private bool updateStarted,installingUpdate;

 private void AddUpdateSettings(FlowLayoutPanel parent)
 {
  parent.Controls.Add(updateInfo);ConstrainText(parent,updateInfo);
  AddSettingsActions(parent,installUpdate,openUpdate).Name="update-actions";
  installUpdate.Enabled=openUpdate.Enabled=false;
  installUpdate.Click+=async(_,_)=>await InstallAvailableUpdate();
  openUpdate.Click+=(_,_)=>Try(()=>{if(availableUpdate is not null)Process.Start(new ProcessStartInfo(availableUpdate.PageUrl){UseShellExecute=true})?.Dispose();});
 }

 private async Task CheckForUpdates()
 {
  if(updateStop.IsCancellationRequested)return;
  try{
   var result=await UpdateCheck.FindNewer(Application.ProductVersion,updateStop.Token);
   if(IsDisposed||updateStop.IsCancellationRequested)return;
   availableUpdate=result;openUpdate.Enabled=result is not null;installUpdate.Enabled=result?.CanInstall==true;
   if(result is null){updateBanner.Visible=false;updateInfo.Text="Новых версий не найдено.";}
   else{updateInfo.Text=result.CanInstall?$"Доступна версия {result.Version}.":$"Доступна версия {result.Version}. Откройте выпуск для установки.";updateBanner.Text=$"Доступна версия {result.Version}. Настройки → Обслуживание.";updateBanner.Visible=true;}
  }catch(OperationCanceledException) when(updateStop.IsCancellationRequested){}
  catch(Exception){if(!IsDisposed)updateInfo.Text="Не удалось проверить обновления.";}
 }

 private void StartUpdateChecks(){if(updateStarted)return;updateStarted=true;updateInfo.Text="Проверяем обновления…";_ = CheckForUpdates();}

 private async Task InstallAvailableUpdate()
 {
  if(installingUpdate||availableUpdate?.CanInstall!=true)return;
  if(worker is not null&&!worker.HasExited){updateInfo.Text="Сначала отключите VPN.";return;}
  string sessions=Path.Combine(Storage.Root,"sessions");
  try{
   if(status.Stage=="recovery_required"||(Directory.Exists(sessions)&&Directory.EnumerateFiles(sessions,"*.json",SearchOption.AllDirectories).Any(p=>Path.GetFileName(p) is "network.json" or "vpn-process.json"))){updateInfo.Text="Сначала восстановите сеть.";return;}
   installingUpdate=true;installUpdate.Enabled=false;updateInfo.Text="Скачиваем и проверяем обновление…";RefreshUi();
   await UpdateInstall.Stage(availableUpdate,updateStop.Token);
   if(IsDisposed||updateStop.IsCancellationRequested)return;
   updateInfo.Text="Открываем новую версию…";Close();
  }catch(OperationCanceledException) when(updateStop.IsCancellationRequested){}
  catch(Exception){if(!IsDisposed)updateInfo.Text="Не удалось установить обновление. Прежняя версия сохранена.";}
  finally{installingUpdate=false;if(!IsDisposed){installUpdate.Enabled=availableUpdate?.CanInstall==true;RefreshUi();}}
 }

 private void StopUpdateChecks()=>updateStop.Cancel();
}
