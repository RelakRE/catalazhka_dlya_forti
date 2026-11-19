using System.Diagnostics;

namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private static readonly string[] trafficUnits=["Б","КБ","МБ","ГБ","ТБ","ПБ","ЭБ"];
 private readonly Label trafficLabel=new(){Name="vpn-traffic",AccessibleName="Трафик VPN",AutoSize=true,Visible=false,Margin=new Padding(0,3,0,3)};
 private SessionTraffic? trafficSession;
 private long? lastTrafficPoll;
 private readonly Button applyWorkAddresses=Btn("Применить рабочие адреса");
 private string? workRequestId;

 private void RefreshTraffic(bool active)
 {
  if(!active||stopRequested)trafficSession=null;
  if(stopRequested||!LaunchGate.CanLaunch(status,active)){
   trafficLabel.Visible=false;
   lastTrafficPoll=null;
   trafficSession?.Pause();
   return;
  }

  long now=Stopwatch.GetTimestamp();
  if(lastTrafficPoll is long last&&Stopwatch.GetElapsedTime(last,now).TotalMilliseconds<900)return;
  lastTrafficPoll=now;

  trafficLabel.Visible=true;
  if(status.TrafficStart is not { } start||TunnelTraffic.Read(start.AdapterId) is not { } current){
   trafficSession?.Pause();
   trafficLabel.Text="Статистика трафика VPN недоступна.";
   return;
  }

  var sample=(trafficSession??=new SessionTraffic()).Measure(start,current,Stopwatch.GetTimestamp());
  trafficLabel.Text=$"Входящий трафик  {TrafficLine(sample.Received,sample.ReceiveRate)}\n"+
                    $"Исходящий трафик  {TrafficLine(sample.Sent,sample.SendRate)}";
 }

 private static string TrafficLine(long bytes,double? rate) =>
  $"{FormatTraffic(bytes)}   ·   {(rate is double speed ? FormatTraffic(speed)+"/с" : "—")}";

 private static string FormatTraffic(double bytes)
 {
  int unit=0;
  while(bytes>=1000&&unit<trafficUnits.Length-1){bytes/=1000;unit++;}
  return $"{bytes:0.#} {trafficUnits[unit]}";
 }

 internal void ShowWorkSites(){ShowSettings();advancedToggle.Checked=true;((ScrollableControl)extra.Parent!.Parent!).ScrollControlIntoView(applyWorkAddresses);}
 private void ApplyWorkAddresses()
 {
  bool active=worker is not null&&!worker.HasExited;
  if(!active){Save();settingsNotice.Text="Рабочие адреса сохранены. IP определятся при подключении.";return;}
  if(folder is null||stopRequested||!LaunchGate.CanLaunch(status,true)||workRequestId is not null)throw new IOException("Дождитесь подключения VPN и завершения обновления адресов.");
  string[] hosts=Config.ParseWorkHosts(extra.Text);
  string[] domains=dnsDomains.Text.Split([',',';','\r','\n',' '],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
  var request=new WorkAddressRequest(Guid.NewGuid().ToString("N"),hosts,domains);
  request.ApplyTo(Storage.Read<Config>(Path.Combine(folder,"config.json")));
  SaveProfile(profile.WithWorkAddresses(hosts,domains));
  Storage.Save(Path.Combine(folder,"work-address-request.json"),request);
  workRequestId=request.Id;settingsNotice.Text="Обновляем адреса рабочих сайтов…";RefreshUi();
 }
 private void CheckWorkAddressResult()
 {
  if(workRequestId is null||folder is null)return;
  string path=Path.Combine(folder,"work-address-result.json");
  if(File.Exists(path)){
   var result=Storage.Read<WorkAddressResult>(path);
   if(result.Id==workRequestId){workRequestId=null;settingsNotice.Text=result.Success?result.Message+" "+status.Message:result.Message;if(!result.Success)MessageBox.Show(result.Message,"Рабочие адреса");}
  }
  if(workRequestId is not null&&(worker is null||worker.HasExited)){workRequestId=null;settingsNotice.Text="Не удалось подтвердить обновление адресов. Проверьте состояние VPN.";}
 }
}
