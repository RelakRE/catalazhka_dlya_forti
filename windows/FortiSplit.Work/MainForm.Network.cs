namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private readonly Button applyWorkAddresses=Btn("Применить рабочие адреса");
 private string? workRequestId;
 internal void ShowWorkSites(){ShowSettings();advancedToggle.Checked=true;((ScrollableControl)extra.Parent!.Parent!).ScrollControlIntoView(applyWorkAddresses);}
 private void ApplyWorkAddresses()
 {
  bool active=worker is not null&&!worker.HasExited;
  if(!active){Save();detail.Text="Рабочие адреса сохранены. IP будут определены при подключении.";return;}
  if(folder is null||stopRequested||!LaunchGate.CanLaunch(status,true)||workRequestId is not null)throw new IOException("Дождитесь готовности VPN и завершения обновления адресов.");
  string[] hosts=Config.ParseWorkHosts(extra.Text);
  string[] domains=dnsDomains.Text.Split([',',';','\r','\n',' '],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
  var request=new WorkAddressRequest(Guid.NewGuid().ToString("N"),hosts,domains);
  request.ApplyTo(Storage.Read<Config>(Path.Combine(folder,"config.json")));
  SaveProfile(profile.WithWorkAddresses(hosts,domains));
  Storage.Save(Path.Combine(folder,"work-address-request.json"),request);
  workRequestId=request.Id;detail.Text="Определяем IP рабочих сайтов через VPN…";RefreshUi();
 }
 private void CheckWorkAddressResult()
 {
  if(workRequestId is null||folder is null)return;
  string path=Path.Combine(folder,"work-address-result.json");
  if(File.Exists(path)){
   var result=Storage.Read<WorkAddressResult>(path);
   if(result.Id==workRequestId){workRequestId=null;if(!result.Success)MessageBox.Show(result.Message,"Рабочие адреса");}
  }
  if(worker is null||worker.HasExited)workRequestId=null;
 }
}
