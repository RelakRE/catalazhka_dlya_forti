using System.Diagnostics;

namespace FortiSplit.Work;

internal sealed partial class MainForm
{
 private static readonly string[] trafficUnits=["Б","КБ","МБ","ГБ","ТБ","ПБ","ЭБ"];
 private SessionTraffic? trafficSession;
 private long? lastTrafficPoll;
 private string? workRequestId;

 private void RefreshTraffic(bool active)
 {
  if(status.WorkTraffic?.RecentEvents is { Length:>0 } events)
   lastActivityEvents=events.Concat(lastActivityEvents)
    .DistinctBy(item=>(item.Peer.Address,item.Activity.StartedUtc,item.Activity.LastActivityUtc))
    .OrderByDescending(item=>item.Activity.LastActivityUtc).Take(TunnelActivity.HistoryLimit).ToArray();
  bool ready=!stopRequested&&LaunchGate.CanLaunch(status,active);
  trafficTitle.Visible=peerHeading.Visible=peerScope.Visible=ready;
  if(!active||stopRequested)trafficSession=null;
  if(!ready){
   trafficOverview.Visible=trafficUnavailable.Visible=peerColumns.Visible=peerEmpty.Visible=false;
   var rows=peerRows.Values.ToArray();
   peerRows.Clear();
   foreach(var row in rows)row.Dispose();
   lastTrafficPoll=null;
   trafficSession?.Pause();
   ShowActivityHistory();
   return;
  }

  long now=Stopwatch.GetTimestamp();
  if(lastTrafficPoll is long last&&Stopwatch.GetElapsedTime(last,now).TotalMilliseconds<900)return;
  lastTrafficPoll=now;

  if(status.TrafficStart is not { } start||TunnelTraffic.Read(start.AdapterId) is not { } current){
   trafficSession?.Pause();
   SetTrafficSummary(null);
  }
  else SetTrafficSummary((trafficSession??=new SessionTraffic()).Measure(start,current,Stopwatch.GetTimestamp()));
  ShowPeerTraffic(status.WorkTraffic,now);
  ShowActivityHistory();
 }

 private void CheckWorkConnection(string? selectedHost=null)
 {
  string? session=folder;
  if(session is null||stopRequested||!LaunchGate.CanLaunch(status,worker is { HasExited:false }))return;
  var network=Storage.Read<WorkNetwork>(Path.Combine(session,"network.json"));
  if(network.Stage!="ready")throw new IOException("Дождитесь завершения настройки рабочих адресов.");
  bool SessionReady()=>folder==session&&!stopRequested&&LaunchGate.CanLaunch(status,worker is { HasExited:false })&&
   Guid.TryParse(network.Guid,out var adapterId)&&status.TrafficStart?.AdapterId==adapterId;
  using var dialog=new WorkConnectionDialog(network,SessionReady,selectedHost);
  dialog.ShowDialog(this);
 }

 private static string FormatTraffic(double bytes)
 {
  int unit=0;
  while(bytes>=1000&&unit<trafficUnits.Length-1){bytes/=1000;unit++;}
  return $"{bytes:0.#} {trafficUnits[unit]}";
 }

 private void ApplyWorkAddresses()
 {
  bool active=worker is not null&&!worker.HasExited;
  if(!active){Save();settingsNotice.Text="Рабочие адреса сохранены. IP определятся при подключении.";return;}
  if(folder is null||stopRequested||!LaunchGate.CanLaunch(status,true)||workRequestId is not null)throw new IOException("Дождитесь подключения VPN и завершения обновления адресов.");
  string[] hosts=WorkAddresses();
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
