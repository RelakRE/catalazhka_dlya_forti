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
 // Windows x64 passes the first printf argument in the fourth argument slot.
 // Read it ONLY for the upstream literal with exactly one %s argument below.
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void ProgressCallback(IntPtr data,int level,IntPtr format,IntPtr firstArgument);
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
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] private static extern int openconnect_get_port(IntPtr info);
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
  Cert cert=(_,_)=>-1;FormCallback form=(_,_)=>1;ProgressCallback progress=(_,_,_,_)=>{};
  IntPtr info=openconnect_vpninfo_new("FortiSplitOfflineCheck",cert,IntPtr.Zero,form,progress,IntPtr.Zero);
  if(info==IntPtr.Zero)return false;
  var endpoint=new Uri("https://vpn.example.com:8443");
  try{return openconnect_set_protocol(info,"fortinet")==0&&openconnect_parse_url(info,endpoint.AbsoluteUri)==0&&
   AuthPolicy.SameOrigin(endpoint,Text(openconnect_get_dnsname(info),254),openconnect_get_port(info));}
  finally{openconnect_vpninfo_free(info);GC.KeepAlive(cert);GC.KeepAlive(form);GC.KeepAlive(progress);}
 }
 internal static AuthSession Authenticate(Config config,Func<AuthRequest,AuthReply> ask,Func<bool> cancelled,Action<string,string?>? stage=null,Action<string>? trace=null)
 {
  ValidateAbi();if(WSAStartup(0x202,new byte[512])!=0)throw new IOException("Не удалось подготовить сетевой клиент.");
  if(openconnect_init_ssl()!=0){WSACleanup();throw new IOException("Не удалось подготовить TLS.");}
  bool rejectedCertificate=false;Exception? callbackFailure=null;
  // Bound only network waits. The user may take as long as needed to enter MFA.
  var responseWait=new AuthResponseWait(Environment.TickCount64);
  var forms=new AuthFormHistory();
  var expectedOrigin=new Uri(config.Server);
  IntPtr info=IntPtr.Zero;
  void VerifyOrigin(){
   if(!AuthPolicy.SameOrigin(expectedOrigin,Text(openconnect_get_dnsname(info),254),openconnect_get_port(info)))
    throw new IOException("VPN перенаправил вход на другой сервер.");
  }
  IOException Stop(AuthFailure failure)
  {
   trace?.Invoke(failure.Kind);
   return new IOException(failure.Message);
  }
  Cert cert=(_,_)=>{rejectedCertificate=true;return -1;};
  ProgressCallback progress=(_,_,format,firstArgument)=>{
   try {
    string formatText=Text(format,128);
    if(formatText=="Got HTTP response: %s\n") {
     if(AuthPolicy.HttpEvent(Text(firstArgument,128)) is { } httpEvent&&responseWait.RecordHttpResponse(httpEvent))
      trace?.Invoke(httpEvent);
    }
    else if(AuthPolicy.ProgressFailure(formatText) is { } problem&&responseWait.RecordResponseProblem(problem))
     trace?.Invoke(problem.Kind);
   }catch(Exception){ /* Diagnostics must never unwind a native callback. */ }
  };
  FormCallback formCallback=(_,pointer)=> {
   try {
    if(cancelled()||responseWait.Failure is not null)return 1;
    var form=Marshal.PtrToStructure<Form>(pointer);var fields=new List<AuthField>();var options=new List<IntPtr>();var seen=new HashSet<IntPtr>();
    string message=Text(form.Message,2048),error=Text(form.Error,1024);
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
    var request=new AuthRequest("form",message,error,fields.ToArray(),Text(form.Id,256));
    if((AuthPolicy.ServerFailure(responseWait.HttpEvent,request,Text(form.Banner,1024))??responseWait.ResponseProblem) is { } serverFailure){
     responseWait.Abort(serverFailure);
     return -1;
    }
     if(fields.Count==0)return 0;
     VerifyOrigin();
    trace?.Invoke("form_"+AuthPolicy.FormCategory(request));
    if(forms.Next(request,out int attempt) is { } formFailure)throw Stop(formFailure);
    request=request with {Attempt=attempt};
    if(!responseWait.BeginForm())return 1;
    stage?.Invoke("form_requested",null);
    AuthReply reply=ask(request);
    if(reply.Cancelled||cancelled()||responseWait.Failure is not null)return 1;
     VerifyOrigin();
    for(int i=0;i<fields.Count;i++){if(!reply.Values.TryGetValue(fields[i].Name,out string? value)||value.Length>4096||value.Contains('\0'))throw new IOException("Неверный ответ формы.");if(openconnect_set_option_value(options[i],value)!=0)throw new IOException("Не удалось заполнить форму.");}
    bool codeSubmitted=AuthPolicy.IsSubmittedCode(request,reply);
    stage?.Invoke(codeSubmitted?"code_submitted":"form_submitted",null);
    responseWait.EndForm(Environment.TickCount64,codeSubmitted);
    return 0;
   }catch(Exception e){callbackFailure=e;return -1;}
  };
   info=openconnect_vpninfo_new("FortiSplit",cert,IntPtr.Zero,formCallback,progress,IntPtr.Zero);
  if(info==IntPtr.Zero){WSACleanup();throw new IOException("Не удалось создать клиент входа.");}
  using var lifetime=new CancellationTokenSource();Task? monitor=null;
  try {
   UIntPtr command=openconnect_setup_cmd_pipe(info);if(command==UIntPtr.MaxValue)throw new IOException("Не подготовлена отмена входа.");
   monitor=Task.Run(async()=>{
    try{
     while(!lifetime.IsCancellationRequested){
      responseWait.TryExpire(Environment.TickCount64);
      var failure=responseWait.Failure;
      if(cancelled()||failure is not null){
       send(command,[(byte)'x'],1,0);
       if(failure is not null)try{stage?.Invoke(failure.Kind,failure.Message);}catch(Exception error) when(error is IOException or UnauthorizedAccessException){ }
       return;
      }
      await Task.Delay(100,lifetime.Token);
     }
    }catch(OperationCanceledException){ }
   });
   if(openconnect_set_protocol(info,"fortinet")!=0||openconnect_parse_url(info,config.Server)!=0)throw new IOException("Неверные параметры VPN.");
   stage?.Invoke("contacting_server",null);
   int result=openconnect_obtain_cookie(info);
   if(responseWait.Complete() is { } terminalFailure)throw Stop(terminalFailure);
   if(result!=0){
    trace?.Invoke("authentication_stopped");
    if(rejectedCertificate)throw new IOException("Сертификат VPN не прошёл проверку. Подключение остановлено.");
    if(callbackFailure is not null)throw new IOException(callbackFailure.Message,callbackFailure);
    if(cancelled()||result==1)throw new OperationCanceledException();
    if(responseWait.ResponseProblem is { } problem)throw Stop(problem);
    string? httpEvent=responseWait.HttpEvent;
    if(AuthPolicy.ServerFailure(httpEvent) is { } serverFailure)throw Stop(serverFailure);
    if(httpEvent=="http_401")throw Stop(new("auth_not_authorized","Сервер VPN не подтвердил вход (HTTP 401). "+AuthPolicy.RetryLater));
    if(httpEvent?.StartsWith("http_4",StringComparison.Ordinal)==true)
     throw Stop(new("auth_http_error",$"Вход в VPN завершился ошибкой HTTP {httpEvent[5..]}."));
    throw Stop(new("auth_client_error",$"Ошибка входа в VPN (код OpenConnect {result})."));
   }
   string cookie=Text(openconnect_get_cookie(info),65536),url=Text(openconnect_get_connect_url(info)),dns=Text(openconnect_get_dnsname(info)),address=Text(openconnect_get_hostname(info));
   if(cookie.Length==0||cookie.Contains('\n')||cookie.Contains('\r'))throw new IOException("VPN не выдал сеанс входа.");
    VerifyOrigin();
   stage?.Invoke("cookie_obtained",null);
   return new(cookie,url,Config.GatewayResolve(dns,address));
  }finally{lifetime.Cancel();monitor?.GetAwaiter().GetResult();openconnect_vpninfo_free(info);WSACleanup();GC.KeepAlive(cert);GC.KeepAlive(progress);GC.KeepAlive(formCallback);}
 }
}
