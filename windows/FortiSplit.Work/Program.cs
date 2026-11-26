using System.Diagnostics;

namespace FortiSplit.Work;
internal static class Program
{
 [STAThread] private static int Main(string[] args)
 {
  if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) return 2;
  if(args.Length==4 && args[0] is ("--worker" or "--recover" or "--bootstrap-worker" or "--bootstrap-recover") && Guid.TryParseExact(args[1],"N",out var session) &&
     int.TryParse(args[2],out int pid) && pid>0 && long.TryParse(args[3],out long ticks)){
   bool bootstrap=args[0].StartsWith("--bootstrap-",StringComparison.Ordinal);
   try{return args[0].EndsWith("worker",StringComparison.Ordinal)?Worker.Run(session.ToString("N"),pid,ticks,bootstrap):Worker.Recover(session.ToString("N"),pid,ticks,bootstrap);}
   catch(Exception error) when(error is IOException or System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException or UnauthorizedAccessException){return 2;}
  }
  ApplicationConfiguration.Initialize();
  if(args.Length==2&&args[0]=="--complete-update")return UpdateInstall.Complete(args[1]);
  if(args.Length==1&&args[0]=="--prepare-runtime"){
   try{RuntimeSetup.Install(AppContext.BaseDirectory,Console.WriteLine,CancellationToken.None).GetAwaiter().GetResult();return 0;}catch{return 1;}
  }
  if(args.Length==2&&args[0]=="--self-test")return OfflineChecks.Run(args[1]).GetAwaiter().GetResult();
  if(args.Length==2 && args[0].StartsWith("--preview",StringComparison.Ordinal)) {
   using Form form=args[0].StartsWith("--preview-help-",StringComparison.Ordinal)?new SettingsHelpDialog(SettingsHelp.Get(args[0]["--preview-help-".Length..])):args[0] is "--preview-auth" or "--preview-otp" or "--preview-otp-repeat"?new AuthDialog(args[0]=="--preview-auth"?new("form","Вход в рабочий VPN","",[new("username","Username",1,[]),new("password","Password",2,[])],"_login"):new("form","Введите одноразовый код из приложения подтверждения","",[new("credential","Token",5,[])],Attempt:args[0]=="--preview-otp-repeat"?2:1),new Config{User="sample.user"},null):new MainForm(true);
   if(args[0]=="--preview-settings"&&form is MainForm main)main.ShowSettings();
   form.Show(); Application.DoEvents();
   if(args[0]=="--preview-sites"&&form is MainForm sites){sites.ShowWorkSites();Application.DoEvents();}
   using var bmp=new Bitmap(form.Width,form.Height); form.DrawToBitmap(bmp,new Rectangle(Point.Empty,bmp.Size)); bmp.Save(Path.GetFullPath(args[1])); return 0;
  }
  if(args.Length!=0) return 2;
  string? forward;
  if(UpdateInstall.IsUpdateLaunch())forward=UpdateInstall.ForwardTarget(true);
  else using(var updateGate=UpdateInstall.AcquireLaunchGate()){
   if(updateGate is null){MessageBox.Show("Дождитесь завершения обновления.","Forti Split");return 1;}
   try{forward=UpdateInstall.ForwardTarget();}finally{updateGate.ReleaseMutex();}
  }
  if(forward is not null){try{using var next=Process.Start(new ProcessStartInfo(forward){UseShellExecute=true});if(next is null)throw new IOException();return 0;}catch(Exception){if(!UpdateInstall.ResetForward(forward)){MessageBox.Show("Не удалось открыть обновлённую версию.","Forti Split");return 1;}MessageBox.Show("Не удалось открыть обновлённую версию. Запускаем прежнюю.","Forti Split");}}
  using var mutex=new Mutex(true,@"Local\FortiSplitWork-UI",out bool first);
  if(!first) { MessageBox.Show("Forti Split уже открыт. Найдите значок рядом с часами."); return 0; }
  try { Storage.Protect(Storage.Root); UpdateInstall.RemoveOldStaging(); Application.Run(new MainForm(false)); return 0; }
  catch(Exception e) { MessageBox.Show(e.Message,"Forti Split"); return 1; }
 }
}
