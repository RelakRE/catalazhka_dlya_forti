using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;

namespace FortiSplit.Work;

internal sealed partial class MainForm : Form
{
 private readonly bool preview;
 private Config profile=new();
 private readonly Label state = new() { Text="VPN отключён",AutoSize=true,Font=new Font("Segoe UI",23),MaximumSize=new Size(650,0),Margin=new Padding(0,3,0,3) };
 private readonly Label detail = new() { Text="Перед подключением отключите FortiClient.",AutoSize=true,MaximumSize=new Size(650,0),Margin=new Padding(0,3,0,3) };
 private readonly Label duration = new() { AutoSize=true,ForeColor=SystemColors.GrayText,Margin=new Padding(0,3,0,3) };
 private readonly Label settingsNotice = new() { Name="save-notice",Dock=DockStyle.Fill,AutoEllipsis=true,AccessibleName="Результат настройки" };
 private readonly Button saveSettings = Btn("Сохранить настройки");
 private readonly Button connect=Btn("Подключить"), rdpButton=Btn("Открыть RDP"), tcButton=Btn("Открыть TrueConf"), restore=Btn("Восстановить сеть"), logs=Btn("Открыть журнал");
 private readonly TextBox server=Box(), user=Box(), rdp=Box(), tc=Box(), tcHost=Box(), dnsDomains=Box();
 private readonly CheckBox autoRdp=Check("Открывать RDP после подключения"), autoTc=Check("Открывать TrueConf после подключения"), autoConnect=Check("Подключаться при открытии приложения");
 private readonly NumericUpDown tcPort=new(){Minimum=1,Maximum=65535,Value=4307,Width=120};
 private readonly System.Windows.Forms.Timer poll=new(){Interval=500};
 private NotifyIcon? tray; private Process? worker; private EventWaitHandle? stop;
 private string? folder, inputFolder; private bool launched, closing, polling, stopRequested, recovering; private DateTime? connectedAt;
 private IDisposable? bootstrapSource;
 private Status status=new("disconnected","Перед подключением отключите FortiClient.",Restored:true);
 private readonly TabControl tabs=new(){Dock=DockStyle.Fill}; private readonly List<Control> options=[];
 private static Button Btn(string text)=>new(){Text=text,Width=210,Height=44,FlatStyle=FlatStyle.Flat,Margin=new Padding(0,6,12,6)};
 private static TextBox Box()=>new(){Width=100,Margin=new Padding(0,3,0,3)};
 private static CheckBox Check(string text)=>new(){Text=text,AutoSize=true,Margin=new Padding(0,8,0,8)};
 private static FlowLayoutPanel Column()=>new(){Dock=DockStyle.Fill,AutoScroll=true,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new Padding(20)};
 private static void FillWidth(FlowLayoutPanel parent,Control child)
 {
  void Fit(){int available=Math.Max(120,parent.ClientSize.Width-parent.Padding.Horizontal-child.Margin.Horizontal);if(child.Width!=available)child.Width=available;}
  parent.ClientSizeChanged+=(_,_)=>Fit();child.VisibleChanged+=(_,_)=>Fit();Fit();
 }
 private static void ConstrainText(FlowLayoutPanel parent,Label label)
 {
  void Fit(){int available=Math.Max(120,parent.ClientSize.Width-parent.Padding.Horizontal-label.Margin.Horizontal);var size=new Size(available,0);if(label.MaximumSize!=size)label.MaximumSize=size;}
  parent.ClientSizeChanged+=(_,_)=>Fit();Fit();
 }
 private static TableLayoutPanel ButtonPair(Button left,Button right)
 {
  var row=new TableLayoutPanel{AutoSize=false,Height=52,ColumnCount=2,RowCount=1,Margin=new Padding(0,0,0,6)};
  row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
  row.RowStyles.Add(new RowStyle(SizeType.Percent,100));
  left.Dock=right.Dock=DockStyle.Fill;left.Margin=new Padding(0,4,6,4);right.Margin=new Padding(6,4,0,4);
  row.Controls.Add(left,0,0);row.Controls.Add(right,1,0);return row;
 }
 internal MainForm(bool preview)
 {
  this.preview=preview; try{Icon=System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!);}catch(Exception){} Text="Forti Split · "+Application.ProductVersion.Split('+')[0]; Font=new Font("Segoe UI",11); AutoScaleMode=AutoScaleMode.Font; MinimumSize=new Size(620,480); MaximumSize=new Size(620,10000); Size=new Size(620,720); MaximizeBox=false;
  var work=new TabPage("Работа"){Name="work"}; var settings=new TabPage("Настройки"){Name="settings"}; tabs.TabPages.AddRange([work,settings]); Controls.Add(tabs);
  var main=Column();main.Name="work-content";work.Controls.Add(main);
  BuildWorkView(main);
  BuildSettingsView(settings);
  Config initial=new();
  if(!preview) {
   string path=Path.Combine(Storage.Root,"settings.json"); if(File.Exists(path)) {try{initial=Storage.Read<Config>(path);}catch(Exception){detail.Text="Не удалось прочитать настройки. Проверьте вкладку «Настройки».";}}
  }
  Apply(initial);
  connect.Name="connection-action";connect.AccessibleDescription="Подключить или отключить VPN";
  rdpButton.Enabled=tcButton.Enabled=false;
  connect.Click+=(_,_)=>{if(worker is not null&&!worker.HasExited)RequestStop();else Try(Start);};
  rdpButton.Click+=(_,_)=>Try(()=>LaunchApp(false));tcButton.Click+=(_,_)=>Try(()=>LaunchApp(true));
  restore.Click+=(_,_)=>Try(Recover);logs.Click+=(_,_)=>Try(OpenLog);
  if(!preview) {
   tray=new NotifyIcon {Icon=Icon,Text="Forti Split",Visible=true};
   var menu=new ContextMenuStrip(); menu.Items.Add("Открыть",null,(_,_)=>ShowWindow());menu.Items.Add("Подключить",null,(_,_)=>Try(Start));menu.Items.Add("Отключить",null,(_,_)=>RequestStop());menu.Items.Add("Выход",null,(_,_)=>Close());tray.ContextMenuStrip=menu;tray.DoubleClick+=(_,_)=>ShowWindow();
   Resize+=(_,_)=>{if(WindowState==FormWindowState.Minimized)Hide();};
   poll.Tick+=(_,_)=>Poll();poll.Start();
   Shown+=async(_,_)=>{
    bool updateLaunch=UpdateInstall.IsUpdateLaunch();
    if(updateLaunch){installingUpdate=true;RefreshUi();}
    if(ClientSize.Height>=300&&connect.Visible&&connect.Width>0)UpdateInstall.SignalReady();
    if(updateLaunch){
     bool committed=await UpdateInstall.WaitForCommit();if(IsDisposed)return;
     if(!committed){detail.Text="Не удалось подтвердить обновление. Откройте прежнюю версию или установите выпуск вручную из ZIP.";return;}
     installingUpdate=false;RefreshUi();
    }
    StartUpdateChecks();if(initial.ConnectOnOpen)Try(Start);
   };
  }
  FormClosing+=(_,e)=>{if(worker is not null && !worker.HasExited){e.Cancel=true;closing=true;RequestStop();ShowWindow();}else{poll.Stop();StopUpdateChecks();CancelAuth();tray?.Dispose();stop?.Dispose();worker?.Dispose();bootstrapSource?.Dispose();}};
 }
 private void Try(Action action){try{action();}catch(Exception e){detail.Text=e.Message;MessageBox.Show(e.Message,"Forti Split");}}
 private void Choose(TextBox field,string filter){using var dialog=new OpenFileDialog{Filter=filter,CheckFileExists=true};if(dialog.ShowDialog()==DialogResult.OK)field.Text=dialog.FileName;}
 private void Apply(Config c){profile=c;server.Text=c.Server;user.Text=c.User;rdp.Text=c.Rdp;tc.Text=c.TrueConf;tcHost.Text=c.TrueConfHost;tcPort.Value=c.TrueConfPort;autoRdp.Checked=c.AutoRdp;autoTc.Checked=c.AutoTrueConf;autoConnect.Checked=c.ConnectOnOpen;rememberPassword.Checked=c.RememberPassword;workAddresses.Items.Clear();workAddresses.Items.AddRange(c.ExtraHosts);workAddressInput.Clear();dnsDomains.Text=string.Join(", ",c.DnsDomains);RefreshWorkAddressEditor();}
 private Config Save(){var c=new Config{Server=server.Text.Trim(),User=user.Text.Trim(),RememberPassword=rememberPassword.Checked,Rdp=rdp.Text.Trim(),TrueConf=tc.Text.Trim(),TrueConfHost=tcHost.Text.Trim(),TrueConfFallback=tcHost.Text.Trim().Equals(profile.TrueConfHost,StringComparison.OrdinalIgnoreCase)?profile.TrueConfFallback:"",TrueConfPort=(int)tcPort.Value,AutoRdp=autoRdp.Checked,AutoTrueConf=autoTc.Checked,ConnectOnOpen=autoConnect.Checked,DnsDomains=dnsDomains.Text.Split([',', ';' ],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries),ExtraHosts=WorkAddresses()};c.Validate();c.PrepareRdp(c.Rdp.Length>0?File.ReadAllText(c.Rdp):"");SaveProfile(c);return c;}
 private void Start()
 {
  if(preview || installingUpdate || recovering || worker is not null && !worker.HasExited)return;
  if(status.Stage=="recovery_required")throw new IOException("Сначала нажмите «Восстановить сеть» и дождитесь подтверждения очистки. Затем подключитесь заново.");
  Config c=Save();string id=Guid.NewGuid().ToString("N");string sessionFolder=Storage.SessionPath(id);
  Storage.Protect(sessionFolder);Storage.Save(Path.Combine(sessionFolder,"config.json"),c);
  var info=WorkerStartInfo("worker",id);
  var sessionStop=new EventWaitHandle(false,EventResetMode.ManualReset,Worker.StopName(id));
  int workerId;
  try {
   BeginAuth(id);
   workerId=StartWorker(info,WorkerOutput(id));
  }catch{
   CancelAuth();authStop?.Dispose();authStop=null;sessionStop.Dispose();throw;
  }
  stop?.Dispose();stop=sessionStop;inputFolder=sessionFolder;
  _=ServeAuth(workerId,c);
  trafficSession=null;
  workRequest=null;launched=false;stopRequested=false;recovering=false;closing=false;connectedAt=null;status=new("preparing","Подключаем VPN…");RefreshUi();
 }
 private static string WorkerOutput(string id)
 {
  using var identity=WindowsIdentity.GetCurrent();
  return NetworkScripts.SessionPath(identity.User!.Value,id);
 }
 private static ProcessStartInfo WorkerStartInfo(string mode,string id)
 {
  string installed=NetworkScripts.WorkerExecutable;
  bool bootstrap=!File.Exists(installed);
  var info=new ProcessStartInfo(bootstrap?Environment.ProcessPath!:installed){
   UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden,
   WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.System)
  };
  using var self=Process.GetCurrentProcess();
  foreach(var arg in new[]{(bootstrap?"--bootstrap-":"--")+mode,id,self.Id.ToString(),self.StartTime.ToUniversalTime().Ticks.ToString()})
   info.ArgumentList.Add(arg);
  return info;
 }
 private int StartWorker(ProcessStartInfo info,string sessionFolder)
 {
  IDisposable? source=info.ArgumentList.FirstOrDefault()?.StartsWith("--bootstrap-",StringComparison.Ordinal)==true
   ? UpdateInstall.OpenBootstrapExecutable(info.FileName) : null;
  try{
   var next=Process.Start(info)??throw new IOException("Не удалось запустить сетевой компонент.");
   worker?.Dispose();worker=next;folder=sessionFolder;
   bootstrapSource?.Dispose();bootstrapSource=source;source=null;
   return next.Id;
  }finally{source?.Dispose();}
 }
  private void RequestStop(){if(recovering || worker is null || worker.HasExited)return;stopRequested=true;CancelAuth();stop?.Set();status=new("disconnecting","Ожидаем отключения и очистки сети…");RefreshUi();}
 private void Poll()
 {
  if(polling || worker is null)return;polling=true;
  try {
   bool alive=!worker.HasExited;
   string? path=folder is null?null:Path.Combine(folder,"status.json");
   if(path is not null && File.Exists(path))try{status=Storage.Read<Status>(path);}catch(IOException){}
   if(alive&&folder is not null&&status.Stage=="connected"&&!Worker.NetworkReady(folder,status))
    status=new("reconnecting","Восстанавливаем соединение и сетевые настройки…",WorkTraffic:status.WorkTraffic);
   if(LaunchGate.CanLaunch(status,alive) && !stopRequested && !launched) {
    launched=true;connectedAt=DateTime.UtcNow;
    Config c=Storage.Read<Config>(Path.Combine(folder!,"config.json"));
    if(c.AutoRdp)LaunchApp(false);if(c.AutoTrueConf)LaunchApp(true);
   }
    if(!alive)CompleteWorker(worker.ExitCode);
   CheckWorkAddressResult();RefreshUi();if(closing && !alive){closing=false;Close();}
  }catch(Exception e){detail.Text=e.Message;}finally{polling=false;}
 }
 private void LaunchApp(bool trueconf)
 {
  if(folder is null || stopRequested || !LaunchGate.CanLaunch(status,worker is not null&&!worker.HasExited) || !Worker.NetworkReady(folder,status))throw new IOException("Сначала дождитесь подключения VPN.");
  Config c=Storage.Read<Config>(Path.Combine(folder,"config.json"));
  if(trueconf){Config.LocalFile(c.TrueConf,".exe");if(!Process.GetProcessesByName(Path.GetFileNameWithoutExtension(c.TrueConf)).Any())Process.Start(new ProcessStartInfo(c.TrueConf){UseShellExecute=true})?.Dispose();}
  else{Config.LocalFile(c.Rdp,".rdp");var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","mstsc.exe")){UseShellExecute=false};info.ArgumentList.Add(c.Rdp);Process.Start(info)?.Dispose();}
 }
 private void Recover()
 {
   if(recovering || worker is not null&&!worker.HasExited)throw new IOException("Сначала отключите текущий VPN-сеанс.");
   string id=Guid.NewGuid().ToString("N");
   StartWorker(WorkerStartInfo("recover",id),WorkerOutput(id));
   stop?.Dispose();stop=null;stopRequested=false;workRequest=null;connectedAt=null;inputFolder=null;
   recovering=true;status=new("disconnecting","Восстанавливаем сеть…");launched=true;RefreshUi();
 }
  private void CompleteWorker(int exitCode)
 {
   bootstrapSource?.Dispose();bootstrapSource=null;
   if(exitCode==Worker.AccountMismatchExitCode){
    status=new(recovering?"recovery_required":"error",Worker.AccountMismatchMessage);
    CancelAuth();
    worker?.Dispose();worker=null;stop?.Dispose();stop=null;
   }else{
    if(recovering&&folder is not null)FinishRecovery(folder);
    if(exitCode==2&&!recovering&&status.Stage=="preparing")
     status=new("error","Не удалось запустить сетевой компонент. Проверьте права доступа и повторите подключение.");
    else if(status.Stage is not ("disconnected" or "error" or "recovery_required"))
     status=new("recovery_required","Не удалось подтвердить восстановление сети.");
   }
   recovering=false;
 }
 private void FinishRecovery(string resultFolder)
 {
  string report=Path.Combine(resultFolder,"recovered-sessions.json");
  if(!File.Exists(report))return;
  try{
   foreach(var session in Storage.Read<RecoveredSession[]>(report)){
    string legacy=Storage.SessionPath(session.Id);
    if(!Directory.Exists(legacy))continue;
    if(session.Network)File.Delete(Path.Combine(legacy,"network.json"));
    if(session.Client)File.Delete(Path.Combine(legacy,"vpn-process.json"));
   }
   if(status.Restored&&Storage.SessionsWithRecoveryFiles().Any())
    status=new("recovery_required","Найдена копия старого журнала без защищённого оригинала. Для восстановления сети обратитесь к администратору.");
  }catch(IOException){
   status=new("recovery_required","Не удалось очистить старые локальные отчёты. Повторите восстановление сети.");
  }catch(UnauthorizedAccessException){
   status=new("recovery_required","Нет доступа к старым локальным отчётам.");
  }
 }
 private void OpenLog(){string path=folder??Storage.Root;var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe")){UseShellExecute=true};info.ArgumentList.Add(path);Process.Start(info)?.Dispose();}
 private void RefreshUi(){
  bool active=recovering||worker is not null&&!worker.HasExited;
  state.Text=status.Stage switch{"connected"=>"VPN подключён","authenticating"=>"Вход в VPN","configuring"=>"Настраиваем сеть…","reconnecting"=>"Восстанавливаем соединение…","disconnecting"=>"Отключаемся…","recovery_required"=>"Нужно восстановить сеть","error"=>"Нет подключения","preparing"=>"Подключаемся…",_=>"VPN отключён"};
  detail.Text=status.Message;
  detail.Visible=status.Message!="VPN подключён.";
  if(status.Stage=="recovery_required")
   detail.Text=(status.Message+" Откройте «Настройки» и нажмите «Восстановить сеть».").TrimStart();
  var action=ConnectionAction.From(status,active,stopRequested,recovering);
  connect.Text=action.Text;connect.Enabled=action.Enabled&&!installingUpdate;restore.Enabled=!active&&!installingUpdate;
  StyleConnectionButton(action.StopsSession);
  rdpButton.Enabled=tcButton.Enabled=!stopRequested&&LaunchGate.CanLaunch(status,active);
  foreach(var option in options)option.Enabled=!active&&!installingUpdate;
  bool addressesEditable=!installingUpdate&&(!active||(!stopRequested&&LaunchGate.CanLaunch(status,active)&&workRequest is null));
  workAddressInput.Enabled=dnsDomains.Enabled=addressesEditable;
  RefreshSettingsState(active,addressesEditable);
  RefreshWorkAddressEditor();
  duration.Text=connectedAt.HasValue&&active?"Время подключения: "+(DateTime.UtcNow-connectedAt.Value).ToString(@"hh\:mm\:ss"):"";
  RefreshTraffic(active);
  if(tray is not null)tray.Text="Forti Split — "+(LaunchGate.CanLaunch(status,active)?"подключён":status.Stage=="recovery_required"?"нужно восстановить сеть":"не подключён");
 }
 private void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
}
