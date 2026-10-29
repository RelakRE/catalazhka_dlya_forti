using System.Diagnostics;
using System.Text.Json;

namespace FortiSplit.Work;

internal sealed partial class MainForm : Form
{
 private readonly bool preview;
 private Config profile=new();
 private readonly Label state = new() { Text="Готово к работе",AutoSize=true,Font=new Font("Segoe UI",23),MaximumSize=new Size(740,0) };
 private readonly Label detail = new() { Text="FortiClient должен быть отключён. Нажмите «Подключить» — клиент VPN откроется автоматически.",AutoSize=true,MaximumSize=new Size(740,0) };
 private readonly Label duration = new() { Text="VPN отключён",AutoSize=true,ForeColor=Color.Teal };
 private readonly Button connect=Btn("Подключить"), disconnect=Btn("Отключить"), rdpButton=Btn("Открыть RDP"), tcButton=Btn("Открыть TrueConf"), restore=Btn("Восстановить сеть"), logs=Btn("Открыть журнал");
 private readonly TextBox server=Box(), user=Box(), rdp=Box(), tc=Box(), tcHost=Box(), extra=Box(), dnsDomains=Box();
 private readonly CheckBox autoRdp=Check("Открывать RDP после подключения"), autoTc=Check("Открывать TrueConf после подключения"), autoConnect=Check("Подключаться при открытии приложения");
 private readonly NumericUpDown tcPort=new(){Minimum=1,Maximum=65535,Value=4307,Width=120};
 private readonly CheckBox advancedToggle=new(){Text="Дополнительные настройки",Appearance=Appearance.Button,AutoSize=true,FlatStyle=FlatStyle.Flat,Margin=new Padding(0,18,0,8)};
 private readonly System.Windows.Forms.Timer poll=new(){Interval=500};
 private NotifyIcon? tray; private Process? worker; private EventWaitHandle? stop;
 private string? folder; private bool launched, closing, polling, stopRequested; private DateTime? connectedAt;
 private Status status=new("disconnected","Готово к работе",Restored:true);
 private readonly TabControl tabs=new(){Dock=DockStyle.Fill}; private readonly List<Control> options=[];
 private static Button Btn(string text)=>new(){Text=text,Width=210,Height=44,FlatStyle=FlatStyle.Flat,Margin=new Padding(0,6,12,6)};
 private static TextBox Box()=>new(){Width=660};
 private static CheckBox Check(string text)=>new(){Text=text,AutoSize=true,Margin=new Padding(0,8,0,8)};
 private static Label Label(string text)=>new(){Text=text,AutoSize=true,MaximumSize=new Size(720,0),Margin=new Padding(0,8,0,6)};
 private static FlowLayoutPanel Column()=>new(){Dock=DockStyle.Fill,AutoScroll=true,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new Padding(24)};
 internal MainForm(bool preview)
 {
  this.preview=preview; Text="Forti Split · "+Application.ProductVersion.Split('+')[0]; ClientSize=new Size(820,690); MinimumSize=new Size(820,700); Font=new Font("Segoe UI",11); BackColor=Color.FromArgb(245,248,250);
  var work=new TabPage("Работа"); var settings=new TabPage("Настройки"); tabs.TabPages.AddRange([work,settings]); Controls.Add(tabs);
  var main=Column();work.Controls.Add(main);
  main.Controls.AddRange([Label("FORTI SPLIT  /  OPENCONNECT"),state,detail,duration]);
  var actions=new FlowLayoutPanel(){Width=730,Height=60}; actions.Controls.AddRange([connect,disconnect]);main.Controls.Add(actions);
  var apps=new FlowLayoutPanel(){Width=730,Height=60}; apps.Controls.AddRange([rdpButton,tcButton]);main.Controls.Add(apps);
  main.Controls.Add(Label("Рабочие серверы — через VPN. Обычные сайты — через ваше подключение к интернету."));
  main.Controls.Add(Label("Вход в VPN — в окне приложения. Одноразовый код запрашивается сервером при подключении."));
  var recovery=new FlowLayoutPanel(){Width=730,Height=60};recovery.Controls.AddRange([restore,logs]); main.Controls.Add(recovery);
  main.Controls.Add(Label("Сверните окно — приложение останется в трее. Закрытие приложения завершает VPN-сеанс и очищает его настройки."));
  var config=Column();settings.Controls.Add(config);
  config.Controls.Add(Label("При подключении"));
  HelpOption(config,"auto-rdp",autoRdp);HelpOption(config,"auto-tc",autoTc);HelpOption(config,"auto-connect",autoConnect);
  HelpField(config,"login",user);HelpOption(config,"remember",rememberPassword);
  HelpField(config,"rdp",rdp);
  var chooseRdp=Btn("Выбрать файл RDP…");config.Controls.Add(chooseRdp);options.Add(chooseRdp);chooseRdp.Click+=(_,_)=>Choose(rdp,"RDP (*.rdp)|*.rdp");
  config.Controls.Add(HelpRow(advancedToggle,"advanced"));
  var advanced=new FlowLayoutPanel{AutoSize=true,FlowDirection=FlowDirection.TopDown,WrapContents=false,Visible=false,Width=690};config.Controls.Add(advanced);advancedToggle.CheckedChanged+=(_,_)=>advanced.Visible=advancedToggle.Checked;
  HelpField(advanced,"vpn",server);HelpField(advanced,"tc-program",tc);
  var chooseTc=Btn("Выбрать TrueConf…");advanced.Controls.Add(chooseTc);options.Add(chooseTc);chooseTc.Click+=(_,_)=>Choose(tc,"Программа (*.exe)|*.exe");
  HelpField(advanced,"tc-server",tcHost);HelpField(advanced,"tc-port",tcPort);HelpField(advanced,"sites",extra);HelpField(advanced,"domains",dnsDomains);
  extra.Multiline=true;extra.Height=85;extra.ScrollBars=ScrollBars.Vertical;
  applyWorkAddresses.Width=280;advanced.Controls.Add(HelpRow(applyWorkAddresses,"apply-sites"));applyWorkAddresses.Click+=(_,_)=>Try(ApplyWorkAddresses);
  var save=Btn("Сохранить");config.Controls.Add(HelpRow(save,"save"));options.Add(save);save.Click+=(_,_)=>Try(()=>{Save();detail.Text="Настройки сохранены.";});
  var profiles=new FlowLayoutPanel{Width=690,AutoSize=true};var import=Btn("Импорт профиля…");var export=Btn("Экспорт профиля…");profiles.Controls.AddRange([HelpRow(import,"import"),HelpRow(export,"export")]);config.Controls.Add(profiles);options.Add(import);options.Add(export);
  import.Click+=(_,_)=>Try(()=>{using var dialog=new OpenFileDialog{Filter="Профиль (*.json)|*.json"};if(dialog.ShowDialog()==DialogResult.OK)Apply(Storage.Read<Config>(dialog.FileName));});
  export.Click+=(_,_)=>Try(()=>{Config profile=Save();using var dialog=new SaveFileDialog{Filter="Приватный профиль (*.local.json)|*.local.json",FileName="profile.local.json"};if(dialog.ShowDialog()==DialogResult.OK)Storage.Save(dialog.FileName,profile);});
  Config initial=new();
  if(!preview) {
   string path=Path.Combine(Storage.Root,"settings.json"); if(File.Exists(path)) {try{initial=Storage.Read<Config>(path);}catch(Exception){detail.Text="Не удалось прочитать настройки. Проверьте вкладку «Настройки».";}}
  }
  Apply(initial);
  connect.BackColor=Color.FromArgb(18,104,93);connect.ForeColor=Color.White;
  disconnect.Enabled=rdpButton.Enabled=tcButton.Enabled=false;
  connect.Click+=(_,_)=>Try(Start);disconnect.Click+=(_,_)=>RequestStop();
  rdpButton.Click+=(_,_)=>Try(()=>LaunchApp(false));tcButton.Click+=(_,_)=>Try(()=>LaunchApp(true));
  restore.Click+=(_,_)=>Try(Recover);logs.Click+=(_,_)=>Try(OpenLog);
  if(!preview) {
   tray=new NotifyIcon {Icon=SystemIcons.Application,Text="Forti Split",Visible=true};
   var menu=new ContextMenuStrip(); menu.Items.Add("Открыть",null,(_,_)=>ShowWindow());menu.Items.Add("Подключить",null,(_,_)=>Try(Start));menu.Items.Add("Отключить",null,(_,_)=>RequestStop());menu.Items.Add("Выход",null,(_,_)=>Close());tray.ContextMenuStrip=menu;tray.DoubleClick+=(_,_)=>ShowWindow();
   Resize+=(_,_)=>{if(WindowState==FormWindowState.Minimized)Hide();};
   poll.Tick+=(_,_)=>Poll();poll.Start();
   Shown+=(_,_)=>{if(initial.ConnectOnOpen)Try(Start);};
  }
  FormClosing+=(_,e)=>{if(worker is not null && !worker.HasExited){e.Cancel=true;closing=true;RequestStop();ShowWindow();}else{poll.Stop();CancelAuth();tray?.Dispose();stop?.Dispose();worker?.Dispose();}};
 }
 private void Try(Action action){try{action();}catch(Exception e){detail.Text=e.Message;MessageBox.Show(e.Message,"Forti Split");}}
 private void Choose(TextBox field,string filter){using var dialog=new OpenFileDialog{Filter=filter,CheckFileExists=true};if(dialog.ShowDialog()==DialogResult.OK)field.Text=dialog.FileName;}
 private void Apply(Config c){profile=c;server.Text=c.Server;user.Text=c.User;rdp.Text=c.Rdp;tc.Text=c.TrueConf;tcHost.Text=c.TrueConfHost;tcPort.Value=c.TrueConfPort;autoRdp.Checked=c.AutoRdp;autoTc.Checked=c.AutoTrueConf;autoConnect.Checked=c.ConnectOnOpen;rememberPassword.Checked=c.RememberPassword;extra.Text=string.Join(", ",c.ExtraHosts);dnsDomains.Text=string.Join(", ",c.DnsDomains);}
 private Config Save(){var c=new Config{Server=server.Text.Trim(),User=user.Text.Trim(),RememberPassword=rememberPassword.Checked,Rdp=rdp.Text.Trim(),TrueConf=tc.Text.Trim(),TrueConfHost=tcHost.Text.Trim(),TrueConfFallback=tcHost.Text.Trim().Equals(profile.TrueConfHost,StringComparison.OrdinalIgnoreCase)?profile.TrueConfFallback:"",TrueConfPort=(int)tcPort.Value,AutoRdp=autoRdp.Checked,AutoTrueConf=autoTc.Checked,ConnectOnOpen=autoConnect.Checked,DnsDomains=dnsDomains.Text.Split([',', ';' ],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries),ExtraHosts=Config.ParseWorkHosts(extra.Text)};c.Validate();c.PrepareRdp(c.Rdp.Length>0?File.ReadAllText(c.Rdp):"");SaveProfile(c);return c;}
 private void Start()
 {
  if(preview || worker is not null && !worker.HasExited)return;
  Config c=Save();string id=Guid.NewGuid().ToString("N");folder=Storage.SessionPath(id);Storage.Protect(folder);Storage.Save(Path.Combine(folder,"config.json"),c);
  BeginAuth(id);
  stop?.Dispose();stop=new EventWaitHandle(false,EventResetMode.ManualReset,Worker.StopName(id));
  using var self=Process.GetCurrentProcess(); var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
  foreach(var arg in new[]{"--worker",id,self.Id.ToString(),self.StartTime.ToUniversalTime().Ticks.ToString()})info.ArgumentList.Add(arg);
  worker?.Dispose();try{worker=Process.Start(info)??throw new IOException("Клиент не запущен.");}catch{CancelAuth();throw;}
  _=ServeAuth(worker.Id,c);
  workRequestId=null;launched=false;stopRequested=false;closing=false;connectedAt=null;status=new("preparing","Запускаем клиент VPN…");RefreshUi();
 }
 private void RequestStop(){if(worker is null || worker.HasExited)return;stopRequested=true;CancelAuth();stop?.Set();status=new("disconnecting","Ожидаем отключения и очистки сети…");RefreshUi();}
 private void Poll()
 {
  if(polling || worker is null)return;polling=true;
  try {
   string? path=folder is null?null:Path.Combine(folder,"status.json");
   if(path is not null && File.Exists(path))try{status=Storage.Read<Status>(path);}catch(IOException){}
   bool alive=!worker.HasExited;
   if(LaunchGate.CanLaunch(status,alive) && !stopRequested && !launched) {
    launched=true;connectedAt=DateTime.UtcNow;
    Config c=Storage.Read<Config>(Path.Combine(folder!,"config.json"));
    if(c.AutoRdp)LaunchApp(false);if(c.AutoTrueConf)LaunchApp(true);
   }
   if(!alive && status.Stage is not ("disconnected" or "error" or "recovery_required"))status=new("error","Клиент завершился без подтверждения очистки. Нажмите «Восстановить сеть».");
   CheckWorkAddressResult();RefreshUi();if(closing && !alive){closing=false;Close();}
  }catch(Exception e){detail.Text=e.Message;}finally{polling=false;}
 }
 private void LaunchApp(bool trueconf)
 {
  if(folder is null || stopRequested || !LaunchGate.CanLaunch(status,worker is not null&&!worker.HasExited))throw new IOException("Сначала дождитесь подключения VPN.");
  Config c=Storage.Read<Config>(Path.Combine(folder,"config.json"));
  if(trueconf){Config.LocalFile(c.TrueConf,".exe");if(!Process.GetProcessesByName(Path.GetFileNameWithoutExtension(c.TrueConf)).Any())Process.Start(new ProcessStartInfo(c.TrueConf){UseShellExecute=true})?.Dispose();}
  else{Config.LocalFile(c.Rdp,".rdp");var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","mstsc.exe")){UseShellExecute=false};info.ArgumentList.Add(c.Rdp);Process.Start(info)?.Dispose();}
 }
 private void Recover()
 {
  if(worker is not null&&!worker.HasExited)throw new IOException("Сначала отключите текущий VPN-сеанс.");
  string sessions=Path.Combine(Storage.Root,"sessions");
  var pending=Directory.Exists(sessions)?Directory.EnumerateFiles(sessions,"*.json",SearchOption.AllDirectories).Where(p=>Path.GetFileName(p) is "network.json" or "vpn-process.json").GroupBy(Path.GetDirectoryName).Select(g=>g.First()).OrderBy(File.GetLastWriteTimeUtc).ToArray():[];
  if(pending.Length==0){MessageBox.Show("Незавершённых сетевых изменений не найдено.",Text);return;}
  folder=Path.GetDirectoryName(pending[0])!;string id=Path.GetFileName(folder);Storage.SessionPath(id);
  var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};info.ArgumentList.Add("--recover");info.ArgumentList.Add(id);
  worker?.Dispose();worker=Process.Start(info);status=new("disconnecting","Восстанавливаем предыдущий сеанс…");launched=true;RefreshUi();
 }
 private void OpenLog(){string path=folder??Storage.Root;var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe")){UseShellExecute=true};info.ArgumentList.Add(path);Process.Start(info)?.Dispose();}
 private void RefreshUi(){bool active=worker is not null&&!worker.HasExited;state.Text=status.Stage switch{"connected"=>"VPN-сеанс активен","authenticating"=>"Ожидаем входа","configuring"=>"Готовим рабочую сеть","reconnecting"=>"Восстанавливаем соединение","disconnecting"=>"Завершаем работу","error" or "recovery_required"=>"Нужно внимание","preparing"=>"Подключаемся…",_=>"VPN отключён"};detail.Text=status.Message;connect.Enabled=!active;disconnect.Enabled=active&&!stopRequested;restore.Enabled=!active;rdpButton.Enabled=tcButton.Enabled=!stopRequested&&LaunchGate.CanLaunch(status,active);foreach(var option in options)option.Enabled=!active;bool addressesEditable=!active||(!stopRequested&&LaunchGate.CanLaunch(status,active)&&workRequestId is null);extra.Enabled=dnsDomains.Enabled=applyWorkAddresses.Enabled=addressesEditable;duration.Text=connectedAt.HasValue&&active?"Время работы: "+(DateTime.UtcNow-connectedAt.Value).ToString(@"hh\:mm\:ss"):"Без ограничения длительности сеанса";if(tray is not null)tray.Text="Forti Split — "+(status.Ready?"подключён":"ожидание");}
 private void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
}
