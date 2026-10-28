using System.Reflection;
using System.Runtime.InteropServices;

namespace FortiSplit.Work;

internal sealed record AuthSession(string Cookie,string ConnectUrl,string Resolve);

// OpenConnect 9.12 public ABI, Windows x64. No library progress text is logged.
internal static class NativeAuth
{
 private const string Library="libopenconnect-5.dll";
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Cert(IntPtr data,IntPtr reason);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int FormCallback(IntPtr data,IntPtr form);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void ProgressCallback(IntPtr data,int level,IntPtr format);
 [StructLayout(LayoutKind.Sequential)] private struct Option {public IntPtr Next;public int Type;public IntPtr Name,Label,Value;public uint Flags;public IntPtr Reserved;}
 [StructLayout(LayoutKind.Sequential)] private struct Form {public IntPtr Banner,Message,Error,Id,Method,Action,Options,Group;public int Selection;}
 [StructLayout(LayoutKind.Sequential)] private struct Select {public Option Form;public int Count;public IntPtr Choices;}
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_init_ssl();
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_vpninfo_new([MarshalAs(UnmanagedType.LPUTF8Str)]string agent,Cert cert,IntPtr config,FormCallback form,ProgressCallback progress,IntPtr data);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern void openconnect_vpninfo_free(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_set_protocol(IntPtr info,[MarshalAs(UnmanagedType.LPUTF8Str)]string protocol);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_parse_url(IntPtr info,[MarshalAs(UnmanagedType.LPUTF8Str)]string url);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_set_option_value(IntPtr option,[MarshalAs(UnmanagedType.LPUTF8Str)]string value);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_obtain_cookie(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_get_cookie(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_get_connect_url(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_get_dnsname(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_get_hostname(IntPtr info);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr openconnect_get_version();
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern UIntPtr openconnect_setup_cmd_pipe(IntPtr info);
 [DllImport("ws2_32.dll")] private static extern int send(UIntPtr socket,byte[] data,int length,int flags);
 [DllImport("ws2_32.dll")] private static extern int WSAStartup(ushort version,byte[] data);
 [DllImport("ws2_32.dll")] private static extern int WSACleanup();
 static NativeAuth() => NativeLibrary.SetDllImportResolver(typeof(NativeAuth).Assembly,ResolveLibrary);
 private static IntPtr ResolveLibrary(string name,Assembly assembly,DllImportSearchPath? search) => name==Library?NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory,"client",name),assembly,DllImportSearchPath.UseDllDirectoryForDependencies|DllImportSearchPath.SafeDirectories):IntPtr.Zero;
 private static string Text(IntPtr p,int max=4096) {if(p==IntPtr.Zero)return "";var result=Marshal.PtrToStringUTF8(p)??"";return result[..Math.Min(result.Length,max)];}
 internal static string ValidateAbi() {
  if(IntPtr.Size!=8||Marshal.SizeOf<Option>()!=56||Marshal.SizeOf<Form>()!=72||Marshal.SizeOf<Select>()!=72)throw new IOException("Unsupported OpenConnect ABI");
  return Text(openconnect_get_version());
 }
 internal static bool CheckInitialization(){
  ValidateAbi();if(openconnect_init_ssl()!=0)return false;
  Cert cert=(_,_)=>-1;FormCallback form=(_,_)=>1;ProgressCallback progress=(_,_,_)=>{};
  IntPtr info=openconnect_vpninfo_new("FortiSplitOfflineCheck",cert,IntPtr.Zero,form,progress,IntPtr.Zero);
  if(info==IntPtr.Zero)return false;
  try{return openconnect_set_protocol(info,"fortinet")==0&&openconnect_parse_url(info,"https://vpn.example.com")==0;}
  finally{openconnect_vpninfo_free(info);GC.KeepAlive(cert);GC.KeepAlive(form);GC.KeepAlive(progress);}
 }
 internal static AuthSession Authenticate(Config config,Func<AuthRequest,AuthReply> ask,Func<bool> cancelled,Action<string>? stage=null)
 {
  ValidateAbi();if(WSAStartup(0x202,new byte[512])!=0)throw new IOException("Не удалось подготовить сетевой клиент.");
  if(openconnect_init_ssl()!=0){WSACleanup();throw new IOException("Не удалось подготовить TLS.");}
  bool rejectedCertificate=false;Exception? callbackFailure=null;
  // Bound only network waits. The user may take as long as needed to enter MFA.
  long responseDeadline=Environment.TickCount64+90000;int timedOut=0;
  Cert cert=(_,_)=>{rejectedCertificate=true;return -1;};
  ProgressCallback progress=(_,_,_)=>{};
  FormCallback formCallback=(_,pointer)=> {
   try {
    if(cancelled())return 1;
    var form=Marshal.PtrToStructure<Form>(pointer);var fields=new List<AuthField>();var options=new List<IntPtr>();var seen=new HashSet<IntPtr>();
    for(IntPtr p=form.Options;p!=IntPtr.Zero;) {
     if(!seen.Add(p)||seen.Count>32)throw new IOException("Слишком большая форма входа.");
     var option=Marshal.PtrToStructure<Option>(p);IntPtr current=p;p=option.Next;
     if((option.Flags&1)!=0||option.Type==4)continue;
     if(option.Type is <1 or >5)throw new IOException("Этот способ входа пока не поддерживается.");
     var choices=new List<AuthChoice>();
     if(option.Type==3){var select=Marshal.PtrToStructure<Select>(current);if(select.Count is <1 or >64)throw new IOException("Неверный список входа.");for(int i=0;i<select.Count;i++){IntPtr choice=Marshal.ReadIntPtr(select.Choices,i*IntPtr.Size);choices.Add(new(Text(Marshal.ReadIntPtr(choice),256),Text(Marshal.ReadIntPtr(choice,8),512)));}}
     string name=Text(option.Name,256);if(fields.Any(x=>x.Name==name))throw new IOException("Повторное поле входа.");
     fields.Add(new(name,Text(option.Label,512),option.Type,choices.ToArray()));options.Add(current);
    }
    var request=new AuthRequest("form",Text(form.Message,2048),Text(form.Error,1024),fields.ToArray(),Text(form.Id,256));
    if(fields.Count==0)return 0;
    Volatile.Write(ref responseDeadline,long.MaxValue);
    AuthReply reply;
    try{stage?.Invoke("form_requested");reply=ask(request);}
    finally{Volatile.Write(ref responseDeadline,Environment.TickCount64+90000);}
    if(reply.Cancelled||cancelled())return 1;
    for(int i=0;i<fields.Count;i++){if(!reply.Values.TryGetValue(fields[i].Name,out string? value)||value.Length>4096||value.Contains('\0'))throw new IOException("Неверный ответ формы.");if(openconnect_set_option_value(options[i],value)!=0)throw new IOException("Не удалось заполнить форму.");}
    stage?.Invoke("form_submitted");return 0;
   }catch(Exception e){callbackFailure=e;return -1;}
  };
  IntPtr info=openconnect_vpninfo_new("FortiSplit",cert,IntPtr.Zero,formCallback,progress,IntPtr.Zero);
  if(info==IntPtr.Zero){WSACleanup();throw new IOException("Не удалось создать клиент входа.");}
  using var lifetime=new CancellationTokenSource();Task? monitor=null;
  try {
   UIntPtr command=openconnect_setup_cmd_pipe(info);if(command==UIntPtr.MaxValue)throw new IOException("Не подготовлена отмена входа.");
   monitor=Task.Run(async()=>{try{while(true){bool timeout=Environment.TickCount64>=Volatile.Read(ref responseDeadline);if(cancelled()||timeout){if(timeout)Interlocked.Exchange(ref timedOut,1);send(command,[(byte)'x'],1,0);return;}await Task.Delay(100,lifetime.Token);}}catch(OperationCanceledException){}});
   if(openconnect_set_protocol(info,"fortinet")!=0||openconnect_parse_url(info,config.Server)!=0)throw new IOException("Неверные параметры VPN.");
   stage?.Invoke("contacting_server");
   int result=openconnect_obtain_cookie(info);
   if(Volatile.Read(ref timedOut)!=0){stage?.Invoke("server_timeout");throw new IOException("Сервер VPN не завершил вход за 90 секунд. Проверьте подтверждение входа и повторите подключение. Неверный пароль не подтверждён.");}
   stage?.Invoke(result==0?"cookie_obtained":"authentication_stopped");
   if(result!=0){if(rejectedCertificate)throw new IOException("Сертификат VPN не прошёл проверку. Подключение остановлено.");if(callbackFailure is not null)throw new IOException("Не удалось обработать форму входа.",callbackFailure);if(cancelled()||result==1)throw new OperationCanceledException();throw new IOException("Вход в VPN не выполнен, код "+result+".");}
   string cookie=Text(openconnect_get_cookie(info),65536),url=Text(openconnect_get_connect_url(info)),dns=Text(openconnect_get_dnsname(info)),address=Text(openconnect_get_hostname(info));
   if(cookie.Length==0||cookie.Contains('\n')||cookie.Contains('\r'))throw new IOException("VPN не выдал сеанс входа.");
   var endpoint=new Uri(url);if(endpoint.Scheme!="https"||!endpoint.Host.Equals(new Uri(config.Server).Host,StringComparison.OrdinalIgnoreCase))throw new IOException("VPN перенаправил вход на другой сервер.");
   Config.Host(dns);Config.IPv4(address);
   return new(cookie,url,dns+":"+address);
  }finally{lifetime.Cancel();monitor?.GetAwaiter().GetResult();openconnect_vpninfo_free(info);WSACleanup();GC.KeepAlive(cert);GC.KeepAlive(progress);GC.KeepAlive(formCallback);}
 }
}
