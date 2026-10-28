namespace FortiSplit.Work;
internal static class Program
{
 [STAThread] private static int Main(string[] args)
 {
  if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess) return 2;
  if(args.Length==6 && args[0]=="--watch" && int.TryParse(args[2],out int owner) && long.TryParse(args[3],out long ownerTicks) && int.TryParse(args[4],out int child) && long.TryParse(args[5],out long childTicks))
   return Worker.Watch(args[1],owner,ownerTicks,child,childTicks);
  if(args.Length==4 && args[0]=="--worker" && int.TryParse(args[2],out int pid) && long.TryParse(args[3],out long ticks))
   return Worker.Run(args[1],pid,ticks,false);
  if(args.Length==2 && args[0]=="--recover") return Worker.Run(args[1],0,0,true);
  ApplicationConfiguration.Initialize();
  if(args.Length==2&&args[0]=="--self-test")return OfflineChecks.Run(args[1]).GetAwaiter().GetResult();
  if(args.Length==2 && args[0].StartsWith("--preview",StringComparison.Ordinal)) {
   using Form form=args[0] is "--preview-auth" or "--preview-otp"?new AuthDialog(args[0]=="--preview-auth"?new("form","Вход в рабочий VPN","",[new("username","Username",1,[]),new("password","Password",2,[])],"_login"):new("form","Введите одноразовый код из приложения подтверждения","",[new("credential","Token",5,[])]),new Config{User="sample.user"},null):new MainForm(true);
   if(args[0]=="--preview-settings"&&form is MainForm main)main.ShowSettings();
   form.Show(); Application.DoEvents();
   using var bmp=new Bitmap(form.Width,form.Height); form.DrawToBitmap(bmp,new Rectangle(Point.Empty,bmp.Size)); bmp.Save(Path.GetFullPath(args[1])); return 0;
  }
  if(args.Length!=0) return 2;
  using var mutex=new Mutex(true,@"Local\FortiSplitWork-UI",out bool first);
  if(!first) { MessageBox.Show("Forti Split уже открыт. Найдите значок рядом с часами."); return 0; }
  try { Storage.Protect(Storage.Root); Application.Run(new MainForm(false)); return 0; }
  catch(Exception e) { MessageBox.Show(e.Message,"Forti Split"); return 1; }
 }
}
