using System.Diagnostics;
using System.Text.Json;

namespace FortiSplit.Work;

internal sealed partial class MainForm : Form
{
 private readonly bool preview;
 private Config profile=new();
 private readonly Label state = new() { Text="VPN отключён",AutoSize=true,Font=new Font("Segoe UI",23),MaximumSize=new Size(650,0),Margin=new Padding(0,3,0,3) };
 private readonly Label detail = new() { Text="Перед подключением отключите FortiClient.",AutoSize=true,MaximumSize=new Size(650,0),Margin=new Padding(0,3,0,3) };
 private readonly Label duration = new() { AutoSize=true,ForeColor=SystemColors.GrayText,Margin=new Padding(0,3,0,3) };
 private readonly Label settingsNotice = new() { AutoSize=true,MaximumSize=new Size(650,0),AccessibleName="Результат настройки",Margin=new Padding(0,3,0,3) };
 private readonly Button connect=Btn("Подключить"), rdpButton=Btn("Открыть RDP"), tcButton=Btn("Открыть TrueConf"), restore=Btn("Восстановить сеть"), logs=Btn("Открыть журнал");
 private readonly TextBox server=Box(), user=Box(), rdp=Box(), tc=Box(), tcHost=Box(), extra=Box(), dnsDomains=Box();
 private readonly CheckBox autoRdp=Check("Открывать RDP после подключения"), autoTc=Check("Открывать TrueConf после подключения"), autoConnect=Check("Подключаться при открытии приложения");
 private readonly NumericUpDown tcPort=new(){Minimum=1,Maximum=65535,Value=4307,Width=120};
 private readonly CheckBox advancedToggle=new(){Name="advanced-toggle",Text="▸  Дополнительные настройки",Appearance=Appearance.Button,AutoSize=false,FlatStyle=FlatStyle.Flat,Font=new Font("Segoe UI",11,FontStyle.Bold),TextAlign=ContentAlignment.MiddleLeft,Padding=new Padding(10,0,0,0),Margin=new Padding(0,4,0,4)};
 private readonly System.Windows.Forms.Timer poll=new(){Interval=500};
 private NotifyIcon? tray; private Process? worker; private EventWaitHandle? stop;
 private string? folder; private bool launched, closing, polling, stopRequested, recovering; private DateTime? connectedAt;
 private Status status=new("disconnected","Перед подключением отключите FortiClient.",Restored:true);
 private readonly TabControl tabs=new(){Dock=DockStyle.Fill}; private readonly List<Control> options=[];
 private static Button Btn(string text)=>new(){Text=text,Width=210,Height=44,FlatStyle=FlatStyle.Flat,Margin=new Padding(0,6,12,6)};
 private static TextBox Box()=>new(){Width=100,Margin=new Padding(0,3,0,3)};
 private static CheckBox Check(string text)=>new(){Text=text,AutoSize=true,Margin=new Padding(0,8,0,8)};
 private static Label Label(string text)=>new(){Text=text,AutoSize=true,MaximumSize=new Size(720,0),Margin=new Padding(0,8,0,6)};
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
 private TableLayoutPanel FilePicker(TextBox field,string filter,string name)
 {
  var row=new TableLayoutPanel{Name=name,AutoSize=false,Height=40,ColumnCount=2,RowCount=1,Margin=new Padding(0,0,0,4)};
  row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,44));
  field.Dock=DockStyle.Fill;field.Margin=new Padding(0,5,6,0);
  var browse=new Button{Text="\uE8B7",Font=new Font("Segoe MDL2 Assets",13),AccessibleName=name=="rdp-picker"?"Выбрать файл RDP":"Выбрать TrueConf",Dock=DockStyle.Fill,Height=36,Margin=Padding.Empty};
  browse.Click+=(_,_)=>Choose(field,filter);options.Add(browse);row.Controls.Add(field,0,0);row.Controls.Add(browse,1,0);return row;
 }
 internal MainForm(bool preview)
 {
  this.preview=preview; try{Icon=System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!);}catch(Exception){} Text="Forti Split · "+Application.ProductVersion.Split('+')[0]; Font=new Font("Segoe UI",11); AutoScaleMode=AutoScaleMode.Font; MinimumSize=new Size(620,480); MaximumSize=new Size(620,10000); Size=new Size(620,720); MaximizeBox=false;
  var work=new TabPage("Работа"){Name="work"}; var settings=new TabPage("Настройки"){Name="settings"}; tabs.TabPages.AddRange([work,settings]); Controls.Add(tabs);
  var main=Column();main.Name="work-content";work.Controls.Add(main);
  main.Controls.AddRange([state,detail,duration,connect,updateBanner]);ConstrainText(main,state);ConstrainText(main,detail);ConstrainText(main,updateBanner);connect.Margin=new Padding(0,12,0,6);FillWidth(main,connect);
  var config=Column();config.Name="settings-content";settings.Controls.Add(config);
  var footer=new Panel{Name="settings-footer",Dock=DockStyle.Bottom,Height=98,Padding=new Padding(20,4,20,12)};settings.Controls.Add(footer);footer.SendToBack();
  void AlignFooter(){int right=20+Math.Max(0,footer.ClientSize.Width-config.ClientSize.Width);if(footer.Padding.Right!=right)footer.Padding=new Padding(20,4,right,12);}
  config.ClientSizeChanged+=(_,_)=>AlignFooter();footer.ClientSizeChanged+=(_,_)=>AlignFooter();
  config.Controls.Add(Label("Рабочие приложения"));
  var apps=ButtonPair(rdpButton,tcButton);config.Controls.Add(apps);FillWidth(config,apps);
  config.Controls.Add(Label("Восстановление"));
  var recovery=ButtonPair(restore,logs);config.Controls.Add(recovery);FillWidth(config,recovery);
  config.Controls.Add(Label("При подключении"));
  HelpOption(config,"auto-rdp",autoRdp,false);HelpOption(config,"auto-tc",autoTc,false);HelpOption(config,"auto-connect",autoConnect,false);
  HelpField(config,"login",user);HelpOption(config,"remember",rememberPassword);
  HelpField(config,"rdp",rdp,FilePicker(rdp,"RDP (*.rdp)|*.rdp","rdp-picker"));
  var advancedRow=HelpRow(advancedToggle,"advanced");config.Controls.Add(advancedRow);FillWidth(config,advancedRow);
  var advanced=new FlowLayoutPanel{Name="advanced-content",AutoSize=false,FlowDirection=FlowDirection.TopDown,WrapContents=false,Visible=false,Margin=Padding.Empty};config.Controls.Add(advanced);FillWidth(config,advanced);
  bool sizingAdvanced=false;void FitAdvanced(){if(!advanced.Visible||sizingAdvanced)return;sizingAdvanced=true;try{int height=advanced.GetPreferredSize(new Size(advanced.ClientSize.Width,0)).Height;if(advanced.Height!=height)advanced.Height=height;}finally{sizingAdvanced=false;}}
  advanced.Layout+=(_,_)=>FitAdvanced();advancedToggle.CheckedChanged+=(_,_)=>{advancedToggle.Text=(advancedToggle.Checked?"▾":"▸")+"  Дополнительные настройки";advanced.Visible=advancedToggle.Checked;FitAdvanced();};
  HelpField(advanced,"vpn",server);HelpField(advanced,"tc-program",tc,FilePicker(tc,"Программа (*.exe)|*.exe","trueconf-picker"));
  HelpField(advanced,"tc-server",tcHost);HelpField(advanced,"tc-port",tcPort);HelpField(advanced,"sites",extra);HelpField(advanced,"domains",dnsDomains);
  extra.Multiline=true;extra.Height=85;extra.ScrollBars=ScrollBars.Vertical;
  var applyRow=HelpRow(applyWorkAddresses,"apply-sites");advanced.Controls.Add(applyRow);FillWidth(advanced,applyRow);advanced.Controls.Add(settingsNotice);ConstrainText(advanced,settingsNotice);applyWorkAddresses.Click+=(_,_)=>Try(ApplyWorkAddresses);
  var import=Btn("Импорт профиля…");var export=Btn("Экспорт профиля…");var profiles=ButtonPair(import,export);profiles.Name="profile-actions";var profileRow=HelpRow(profiles,"profiles");config.Controls.Add(profileRow);FillWidth(config,profileRow);options.Add(import);options.Add(export);
  import.Click+=(_,_)=>Try(()=>{using var dialog=new OpenFileDialog{Filter="Профиль (*.json)|*.json"};if(dialog.ShowDialog()==DialogResult.OK)Apply(Storage.Read<Config>(dialog.FileName));});
  export.Click+=(_,_)=>Try(()=>{Config profile=Save();using var dialog=new SaveFileDialog{Filter="Приватный профиль (*.local.json)|*.local.json",FileName="profile.local.json"};if(dialog.ShowDialog()==DialogResult.OK)Storage.Save(dialog.FileName,profile);});
  AddUpdateSettings(config);
  var savedNotice=new Label{Name="save-notice",Dock=DockStyle.Top,Height=22,AccessibleName="Результат сохранения"};
  var save=Btn("Сохранить");save.Name="save-settings";save.BackColor=SystemColors.Highlight;save.ForeColor=SystemColors.HighlightText;save.Font=new Font("Segoe UI",11,FontStyle.Bold);save.Dock=DockStyle.Fill;save.Margin=Padding.Empty;footer.Controls.Add(save);footer.Controls.Add(savedNotice);savedNotice.SendToBack();options.Add(save);save.Click+=(_,_)=>Try(()=>{Save();savedNotice.Text="Настройки сохранены.";});
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
     if(!committed){detail.Text="Не удалось завершить обновление. Закройте приложение и откройте его снова.";return;}
     installingUpdate=false;RefreshUi();
    }
    StartUpdateChecks();if(initial.ConnectOnOpen)Try(Start);
   };
  }
  FormClosing+=(_,e)=>{if(worker is not null && !worker.HasExited){e.Cancel=true;closing=true;RequestStop();ShowWindow();}else{poll.Stop();StopUpdateChecks();CancelAuth();tray?.Dispose();stop?.Dispose();worker?.Dispose();}};
 }
 private void Try(Action action){try{action();}catch(Exception e){detail.Text=e.Message;MessageBox.Show(e.Message,"Forti Split");}}
 private void Choose(TextBox field,string filter){using var dialog=new OpenFileDialog{Filter=filter,CheckFileExists=true};if(dialog.ShowDialog()==DialogResult.OK)field.Text=dialog.FileName;}
 private void Apply(Config c){profile=c;server.Text=c.Server;user.Text=c.User;rdp.Text=c.Rdp;tc.Text=c.TrueConf;tcHost.Text=c.TrueConfHost;tcPort.Value=c.TrueConfPort;autoRdp.Checked=c.AutoRdp;autoTc.Checked=c.AutoTrueConf;autoConnect.Checked=c.ConnectOnOpen;rememberPassword.Checked=c.RememberPassword;extra.Text=string.Join(", ",c.ExtraHosts);dnsDomains.Text=string.Join(", ",c.DnsDomains);}
 private Config Save(){var c=new Config{Server=server.Text.Trim(),User=user.Text.Trim(),RememberPassword=rememberPassword.Checked,Rdp=rdp.Text.Trim(),TrueConf=tc.Text.Trim(),TrueConfHost=tcHost.Text.Trim(),TrueConfFallback=tcHost.Text.Trim().Equals(profile.TrueConfHost,StringComparison.OrdinalIgnoreCase)?profile.TrueConfFallback:"",TrueConfPort=(int)tcPort.Value,AutoRdp=autoRdp.Checked,AutoTrueConf=autoTc.Checked,ConnectOnOpen=autoConnect.Checked,DnsDomains=dnsDomains.Text.Split([',', ';' ],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries),ExtraHosts=Config.ParseWorkHosts(extra.Text)};c.Validate();c.PrepareRdp(c.Rdp.Length>0?File.ReadAllText(c.Rdp):"");SaveProfile(c);return c;}
 private void Start()
 {
  if(preview || installingUpdate || worker is not null && !worker.HasExited)return;
  if(status.Stage=="recovery_required")throw new IOException("Сначала нажмите «Восстановить сеть» и дождитесь подтверждения очистки. Затем подключитесь заново.");
  Config c=Save();string id=Guid.NewGuid().ToString("N");folder=Storage.SessionPath(id);Storage.Protect(folder);Storage.Save(Path.Combine(folder,"config.json"),c);
  BeginAuth(id);
  stop?.Dispose();stop=new EventWaitHandle(false,EventResetMode.ManualReset,Worker.StopName(id));
  using var self=Process.GetCurrentProcess(); var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
  foreach(var arg in new[]{"--worker",id,self.Id.ToString(),self.StartTime.ToUniversalTime().Ticks.ToString()})info.ArgumentList.Add(arg);
  worker?.Dispose();try{worker=Process.Start(info)??throw new IOException("Клиент не запущен.");}catch{CancelAuth();throw;}
  _=ServeAuth(worker.Id,c);
  workRequestId=null;launched=false;stopRequested=false;recovering=false;closing=false;connectedAt=null;status=new("preparing","Подключаем VPN…");RefreshUi();
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
   if(!alive && status.Stage is not ("disconnected" or "error" or "recovery_required"))status=new("recovery_required","Не удалось подтвердить восстановление сети.");
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
  worker?.Dispose();worker=Process.Start(info)??throw new IOException("Не удалось запустить восстановление сети.");recovering=true;status=new("disconnecting","Восстанавливаем сеть…");launched=true;RefreshUi();
 }
 private void OpenLog(){string path=folder??Storage.Root;var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe")){UseShellExecute=true};info.ArgumentList.Add(path);Process.Start(info)?.Dispose();}
 private void RefreshUi(){
  bool active=worker is not null&&!worker.HasExited;
  if(!active)recovering=false;
  state.Text=status.Stage switch{"connected"=>"VPN подключён","authenticating"=>"Вход в VPN","configuring"=>"Настраиваем сеть…","reconnecting"=>"Восстанавливаем соединение…","disconnecting"=>"Отключаемся…","recovery_required"=>"Нужно восстановить сеть","error"=>"Нет подключения","preparing"=>"Подключаемся…",_=>"VPN отключён"};
  detail.Text=status.Message;
  if(status.Stage=="recovery_required")
   detail.Text=(status.Message+" Откройте «Настройки» и нажмите «Восстановить сеть».").TrimStart();
  var action=ConnectionAction.From(status,active,stopRequested,recovering);
  connect.Text=action.Text;connect.Enabled=action.Enabled&&!installingUpdate;restore.Enabled=!active&&!installingUpdate;
  rdpButton.Enabled=tcButton.Enabled=!stopRequested&&LaunchGate.CanLaunch(status,active);
  foreach(var option in options)option.Enabled=!active&&!installingUpdate;
  bool addressesEditable=!installingUpdate&&(!active||(!stopRequested&&LaunchGate.CanLaunch(status,active)&&workRequestId is null));
  extra.Enabled=dnsDomains.Enabled=applyWorkAddresses.Enabled=addressesEditable;
  duration.Text=connectedAt.HasValue&&active?"Время подключения: "+(DateTime.UtcNow-connectedAt.Value).ToString(@"hh\:mm\:ss"):"";
  if(tray is not null)tray.Text="Forti Split — "+(LaunchGate.CanLaunch(status,active)?"подключён":status.Stage=="recovery_required"?"нужно восстановить сеть":"не подключён");
 }
 private void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
}
