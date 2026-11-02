using FortiSplit.Work;
using System.Text.Json;
var results=new Dictionary<string,bool>();
void Check(string name,bool condition)=>results.Add(name,condition);
void Reject(string name,Action action){try{action();Check(name,false);}catch(Exception){Check(name,true);}}
foreach(string host in new[]{"desktop.example.com","gateway.example.com","video.example.com","192.0.2.3"}){Config.Host(host);Check("host_"+host,true);}
foreach(string host in new[]{"localhost","127.0.0.1","0.0.0.0","224.0.0.1","169.254.1.1","::1","a.com & calc.exe","a..com","http://a.com","a.com\r\n","-a.com","a-.com"})Reject("reject_"+host,()=>Config.Host(host));
var config=new Config{Server="https://vpn.example.com",AutoRdp=false,AutoTrueConf=false};
config.PrepareRdp("full address:s:desktop.example.com\ngatewayhostname:s:gateway.example.com\ngatewayusagemethod:i:2\ngatewayprofileusagemethod:i:1");
Check("rdp_hosts_are_hints_only",config.Hosts.Length==0&&config.OptionalHosts.SequenceEqual(new[]{"desktop.example.com","gateway.example.com"}));
config.PrepareRdp("full address:s:desktop.example.com\ngatewayhostname:s:gateway.example.com\ngatewayusagemethod:i:1\ngatewayprofileusagemethod:i:1");
Check("gateway_has_no_mandatory_endpoint",config.Hosts.Length==0&&config.OptionalHosts.Contains("gateway.example.com"));
config.PrepareRdp("full address:s:192.0.2.4:3390\ngatewayusagemethod:i:0");Check("direct_rdp_is_only_route_hint",config.Hosts.Length==0&&config.OptionalHosts.SequenceEqual(new[]{"192.0.2.4"}));
config.PrepareRdp("full address:s:desktop.example.com\ngatewayhostname:s:unused.example.com\ngatewayusagemethod:i:4");
Check("unused_gateway_not_routed",config.OptionalHosts.SequenceEqual(new[]{"desktop.example.com"}));
config.PrepareRdp("full address:s:WORKSTATION-17\ngatewayusagemethod:i:3");Check("short_names_and_system_gateway_allowed",config.Hosts.Length==0&&config.OptionalHosts.Length==0);
config.PrepareRdp("full address:s:another-pc.example.com\ngatewayhostname:s:gateway.example.com\ngatewayusagemethod:i:2\ngatewayprofileusagemethod:i:0");Check("any_target_and_system_gateway_profile_allowed",config.OptionalHosts.Contains("another-pc.example.com"));
config.PrepareRdp("full address:s:foo & calc.exe");Check("unrecognized_endpoint_never_used_as_command_or_route",config.OptionalHosts.Length==0);
config.PrepareRdp("");Check("vpn_without_rdp_target_allowed",config.Hosts.Length==0&&config.OptionalHosts.Length==0);
foreach(string url in new[]{"http://vpn.example","https://a:b@vpn.example","https://vpn.example/?secret=1","https://vpn.example/#x"})Reject("server_"+url,()=>new Config{Server=url,AutoRdp=false}.Validate());
Check("ready_only_launch",LaunchGate.CanLaunch(new("connected","ok",true),true));
Check("no_launch_during_auth",!LaunchGate.CanLaunch(new("authenticating","wait",true),true));
Check("no_stale_launch",!LaunchGate.CanLaunch(new("connected","ok",true),false));
Check("no_launch_without_ready",!LaunchGate.CanLaunch(new("connected","wait",false),true));
Check("action_connect_when_disconnected",ConnectionAction.From(new("disconnected",""),false,false,false)==new ConnectionAction("Подключить",true,false));
Check("action_stop_during_authentication",ConnectionAction.From(new("authenticating",""),true,false,false)==new ConnectionAction("Отключить",true,true));
Check("action_stop_when_connected",ConnectionAction.From(new("connected","",true),true,false,false)==new ConnectionAction("Отключить",true,true));
Check("action_disabled_during_stop",!ConnectionAction.From(new("disconnecting",""),true,true,false).Enabled);
Check("action_disabled_during_recovery",!ConnectionAction.From(new("disconnecting",""),true,false,true).Enabled);
Check("action_connect_blocked_until_recovery",!ConnectionAction.From(new("recovery_required",""),false,false,false).Enabled);
Check("action_connect_after_recovery",ConnectionAction.From(new("disconnected","",false,true),false,false,false).Enabled);
const string releaseCatalog="""
[
 {"tag_name":"v9.0.0","draft":false,"assets":[{"name":"Forti-Split-9.0.0-Windows-x64.zip","state":"uploaded"}]},
 {"tag_name":"windows-v2.0.0","draft":true,"assets":[{"name":"Forti-Split-2.0.0-Windows-x64.zip","state":"uploaded"}]},
 {"tag_name":"windows-v1.2.8","draft":false,"prerelease":true,"html_url":"https://evil.example/","assets":[{"name":"Forti-Split-1.2.8-Windows-x64.zip","state":"uploaded","id":44,"size":4,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]},
 {"tag_name":"windows-v1.2.9","draft":false,"assets":[{"name":"Forti-Split-1.2.9-Windows-x64.zip","state":"new"}]},
 {"tag_name":"windows-v1.2.7","draft":false,"prerelease":true,"assets":[{"name":"Forti-Split-1.2.7-Windows-x64.zip","state":"uploaded"}]},
 {"tag_name":"windows-v1.2.99/evil","draft":false,"assets":[{"name":"Forti-Split-1.2.99-Windows-x64.zip","state":"uploaded"}]}
]
""";
var update=UpdateCatalog.FindNewer(releaseCatalog,UpdateCatalog.CurrentVersion("1.2.6-ui-preview+abc"));
Check("updates_choose_newest_published_windows_preview",update?.Version==new Version(1,2,8));
Check("update_page_is_constructed_from_trusted_repository",update?.PageUrl=="https://github.com/RelakRE/catalazhka_dlya_forti/releases/tag/windows-v1.2.8");
Check("update_requires_github_digest_and_size",update?.CanInstall==true&&new UpdateCandidate(new Version(1,2,8),"",44,"",4).CanInstall==false);
Check("same_version_has_no_update",UpdateCatalog.FindNewer(releaseCatalog,new Version(1,2,8)) is null);
Check("no_releases_has_no_update",UpdateCatalog.FindNewer("[]",new Version(1,2,6)) is null);
Reject("malformed_release_catalog_rejected",()=>UpdateCatalog.FindNewer("{}",new Version(1,2,6)));
Reject("invalid_current_version_rejected",()=>UpdateCatalog.CurrentVersion("1.2.6/evil"));
var updateHandler=new FakeUpdateHandler((request,_)=>Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new StringContent(releaseCatalog)}));
var httpUpdate=await UpdateCheck.FindNewer("1.2.6",CancellationToken.None,updateHandler,TimeSpan.FromSeconds(2));
Check("update_http_uses_fixed_github_endpoint",updateHandler.Url=="https://api.github.com/repos/RelakRE/catalazhka_dlya_forti/releases?per_page=100"&&httpUpdate?.Version==new Version(1,2,8));
var stuckHandler=new FakeUpdateHandler(async(_,token)=>{await Task.Delay(Timeout.Infinite,token);return new HttpResponseMessage();});
try{await UpdateCheck.FindNewer("1.2.6",CancellationToken.None,stuckHandler,TimeSpan.FromMilliseconds(50));Check("update_http_timeout",false);}catch(OperationCanceledException){Check("update_http_timeout",true);}
var stuckBody=new FakeUpdateHandler((_,_)=>Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new StreamContent(new StalledUpdateStream())}));
try{await UpdateCheck.FindNewer("1.2.6",CancellationToken.None,stuckBody,TimeSpan.FromMilliseconds(50));Check("update_body_read_timeout",false);}catch(OperationCanceledException){Check("update_body_read_timeout",true);}
var tooLarge=new FakeUpdateHandler((_,_)=>{var content=new StringContent("x");content.Headers.ContentLength=2*1024*1024+1;return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=content});});
try{await UpdateCheck.FindNewer("1.2.6",CancellationToken.None,tooLarge,TimeSpan.FromSeconds(2));Check("update_response_limit",false);}catch(IOException){Check("update_response_limit",true);}
string? realCatalog=Environment.GetEnvironmentVariable("FORTISPLIT_TEST_PUBLIC_RELEASES");
if(!string.IsNullOrEmpty(realCatalog)){
 var real=UpdateCatalog.FindNewer(File.ReadAllText(realCatalog),new Version(1,2,5));
 Check("actual_github_releases_include_windows_126_or_newer",real is not null&&real.Version>=new Version(1,2,6)&&real.CanInstall);
}
string updateTemp=Path.Combine(Path.GetTempPath(),"FortiSplitUpdateChecks-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(updateTemp);
try{
 byte[] payload=[1,2,3,4];string digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
 var candidate=new UpdateCandidate(new Version(1,2,8),"",44,digest,payload.Length);
 var downloadHandler=new FakeUpdateHandler((_,_)=>Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new ByteArrayContent(payload)}));
 string download=Path.Combine(updateTemp,"download.zip");await UpdateDownload.Download(candidate,download,CancellationToken.None,downloadHandler);
 Check("update_download_verifies_hash_and_length",File.ReadAllBytes(download).SequenceEqual(payload));
 var badHash=new FakeUpdateHandler((_,_)=>Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK){Content=new ByteArrayContent(payload)}));
 try{await UpdateDownload.Download(candidate with {Sha256=new string('0',64)},Path.Combine(updateTemp,"bad.zip"),CancellationToken.None,badHash);Check("update_rejects_wrong_hash",false);}catch(IOException){Check("update_rejects_wrong_hash",true);}
 var badRedirect=new FakeUpdateHandler((_,_)=>{var response=new HttpResponseMessage(System.Net.HttpStatusCode.Redirect);response.Headers.Location=new Uri("https://evil.example/file");return Task.FromResult(response);});
 try{await UpdateDownload.Download(candidate,Path.Combine(updateTemp,"redirect.zip"),CancellationToken.None,badRedirect);Check("update_rejects_foreign_redirect",false);}catch(IOException){Check("update_rejects_foreign_redirect",true);}
 byte[] pe=new byte[256];pe[0]=0x4d;pe[1]=0x5a;pe[60]=64;pe[64]=0x50;pe[65]=0x45;pe[68]=0x64;pe[69]=0x86;
 void WriteArchive(string path,string? extra=null,bool marker=true,int attributes=0){using var zip=System.IO.Compression.ZipFile.Open(path,System.IO.Compression.ZipArchiveMode.Create);void Entry(string name,byte[] content,int attr=0){var entry=zip.CreateEntry(name);if(attr!=0)entry.ExternalAttributes=attr;using var s=entry.Open();s.Write(content);};Entry("Forti Split.exe",pe);Entry("Network.ps1",[1]);Entry("network-hook.js",[2]);Entry("licenses/LICENSE.txt",[3]);if(marker)Entry("fortisplit-update-v1.json",System.Text.Encoding.UTF8.GetBytes("{\"format\":1,\"ready_signal\":true}"));if(extra is not null)Entry(extra,[4],attributes);}
 string archive=Path.Combine(updateTemp,"valid.zip");WriteArchive(archive);string extracted=Path.Combine(updateTemp,"extracted");UpdateArchive.Extract(archive,extracted);
 Check("update_extracts_supported_package",File.Exists(Path.Combine(extracted,"Forti Split.exe"))&&File.Exists(Path.Combine(extracted,"licenses","LICENSE.txt")));
 string traversal=Path.Combine(updateTemp,"traversal.zip");WriteArchive(traversal,"../escape.txt");Reject("update_rejects_zip_traversal",()=>UpdateArchive.Extract(traversal,Path.Combine(updateTemp,"traversal")));
 string duplicate=Path.Combine(updateTemp,"duplicate.zip");WriteArchive(duplicate,"network.PS1");Reject("update_rejects_duplicate_files",()=>UpdateArchive.Extract(duplicate,Path.Combine(updateTemp,"duplicate")));
 string symlink=Path.Combine(updateTemp,"symlink.zip");WriteArchive(symlink,"licenses/link",attributes:unchecked((int)0xA0000000));Reject("update_rejects_zip_symlinks",()=>UpdateArchive.Extract(symlink,Path.Combine(updateTemp,"symlink")));
 string old=Path.Combine(updateTemp,"old.zip");WriteArchive(old,marker:false);Reject("update_requires_restart_capability",()=>UpdateArchive.Extract(old,Path.Combine(updateTemp,"old")));
 string runtime=Path.Combine(updateTemp,"client");Directory.CreateDirectory(runtime);foreach(string name in new[]{"openconnect.exe","libopenconnect-5.dll","libgnutls-30.dll","wintun.dll"})File.WriteAllBytes(Path.Combine(runtime,name),[1]);
 string runtimeCopy=Path.Combine(updateTemp,"client-copy");UpdateRuntime.Copy(runtime,runtimeCopy);Check("update_preserves_vpn_runtime",File.ReadAllBytes(Path.Combine(runtimeCopy,"wintun.dll")).SequenceEqual(new byte[]{1}));
 File.WriteAllBytes(Path.Combine(runtime,"wintun.dll"),[]);Reject("update_rejects_empty_runtime",()=>UpdateRuntime.Copy(runtime,Path.Combine(updateTemp,"empty-client")));
 string? realZip=Environment.GetEnvironmentVariable("FORTISPLIT_TEST_PUBLIC_ZIP");
 if(!string.IsNullOrEmpty(realZip)){
  string adapted=Path.Combine(updateTemp,"real-release.zip");
  using(var original=System.IO.Compression.ZipFile.OpenRead(realZip))using(var future=System.IO.Compression.ZipFile.Open(adapted,System.IO.Compression.ZipArchiveMode.Create)){
   foreach(var entry in original.Entries){var copy=future.CreateEntry(entry.FullName);copy.ExternalAttributes=entry.ExternalAttributes;using var source=entry.Open();using var target=copy.Open();source.CopyTo(target);}
   using var marker=future.CreateEntry("fortisplit-update-v1.json").Open();marker.Write(System.Text.Encoding.UTF8.GetBytes("{\"format\":1,\"ready_signal\":true}"));
  }
  string actual=Path.Combine(updateTemp,"actual-release");UpdateArchive.Extract(adapted,actual);
  Check("published_windows_archive_layout_supported",File.Exists(Path.Combine(actual,"Forti Split.exe"))&&File.Exists(Path.Combine(actual,"Network.ps1")));
 }
}finally{Directory.Delete(updateTemp,true);}
Check("config_has_no_auth_secrets",!JsonSerializer.Serialize(new Config()).Contains("\"Password\"",StringComparison.Ordinal));
string fakeExe=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N")+".exe");
try {
 File.WriteAllBytes(fakeExe,[]);
 var manualTc=new Config{Server="https://vpn.example.com",AutoRdp=false,AutoTrueConf=false,TrueConf=fakeExe,TrueConfHost="video.example.com",TrueConfFallback="192.0.2.20"};
 manualTc.PrepareRdp("full address:s:desktop.example.com");
 Check("manual_trueconf_keeps_vpn_route_hints",manualTc.OptionalHosts.Contains(manualTc.TrueConfHost)&&manualTc.OptionalHosts.Contains(manualTc.TrueConfFallback));
} finally {File.Delete(fakeExe);}
var loginProfile=new Config{User="sample.user",RememberPassword=true};
var bootstrap=new Config{Server="https://vpn.example.com",AutoRdp=false,DnsDomains=["corp.example.com","rdp.example.com"],ExtraHosts=["203.0.113.21","203.0.113.22"]};
bootstrap.PrepareRdp("full address:s:any-computer.corp.example.com\ngatewayhostname:s:gateway.rdp.example.com\ngatewayusagemethod:i:2");
Check("bootstrap_ips_not_dependent_on_pc_name",bootstrap.Hosts.SequenceEqual(bootstrap.ExtraHosts)&&bootstrap.OptionalHosts.Contains("any-computer.corp.example.com"));
var bootstrapRestored=JsonSerializer.Deserialize<Config>(JsonSerializer.Serialize(bootstrap))!;
Check("private_domains_survive_profile_roundtrip",bootstrapRestored.DnsDomains.SequenceEqual(bootstrap.DnsDomains));
Reject("catch_all_dns_domain_rejected",()=>new Config{Server="https://vpn.example.com",AutoRdp=false,DnsDomains=["."]}.Validate());
Reject("ip_as_dns_domain_rejected",()=>new Config{Server="https://vpn.example.com",AutoRdp=false,DnsDomains=["203.0.113.21"]}.Validate());
var restoredProfile=JsonSerializer.Deserialize<Config>(JsonSerializer.Serialize(loginProfile))!;
Check("site_urls_normalize_to_unique_names",Config.ParseWorkHosts("https://Help.example.com/a?ReturnUrl=/b, help.example.com; https://ws.example.com:8042/path\n192.0.2.10").SequenceEqual(new[]{"help.example.com","ws.example.com","192.0.2.10"}));
Reject("site_url_credentials_rejected",()=>Config.ParseWorkHosts("https://user:password@site.example.com/path"));
Reject("site_url_scheme_rejected",()=>Config.ParseWorkHosts("ftp://site.example.com/path"));
Reject("site_subnet_rejected",()=>Config.ParseWorkHosts("192.0.2.0/24"));
var addressRequest=new WorkAddressRequest(Guid.NewGuid().ToString("N"),["site.example.com"],["corp.example.com"]);
var changedNetwork=addressRequest.ApplyTo(bootstrap);
Check("live_update_changes_only_work_addresses",changedNetwork.Server==bootstrap.Server&&changedNetwork.Rdp==bootstrap.Rdp&&changedNetwork.OptionalHosts.SequenceEqual(bootstrap.OptionalHosts)&&changedNetwork.Hosts.SequenceEqual(new[]{"site.example.com"})&&changedNetwork.DnsDomains.SequenceEqual(new[]{"corp.example.com"}));
Reject("invalid_live_request_rejected",()=>new WorkAddressRequest("bad-id",[],[]).ApplyTo(bootstrap));
Reject("live_request_loopback_rejected",()=>new WorkAddressRequest(Guid.NewGuid().ToString("N"),["127.0.0.1"],[]).ApplyTo(bootstrap));
var retryClock=DateTime.UtcNow;var dnsRetry=new WorkDnsRetries();dnsRetry.Reset(true,retryClock);
Check("dns_retry_waits_after_connect",!dnsRetry.TakeDue(retryClock.AddSeconds(2))&&dnsRetry.TakeDue(retryClock.AddSeconds(3)));
Check("dns_retries_are_bounded",dnsRetry.TakeDue(retryClock.AddSeconds(13))&&dnsRetry.TakeDue(retryClock.AddSeconds(43))&&!dnsRetry.TakeDue(retryClock.AddDays(1))&&dnsRetry.Attempts==3);
dnsRetry.Reset(true,retryClock);dnsRetry.Complete(false);Check("dns_retry_stops_on_success",!dnsRetry.TakeDue(retryClock.AddDays(1)));
Check("login_saved_and_reloaded",restoredProfile.User==loginProfile.User&&restoredProfile.RememberPassword);
var passwordField=new AuthField("password","Password",2,[]);
var otpField=new AuthField("credential","Token",2,[]);
Check("initial_password_save_allowed",AuthPolicy.IsPassword(passwordField,new("form","Login","",[new("username","Username",1,[]),passwordField],"_login")));
Check("otp_not_saved",!AuthPolicy.IsPassword(otpField,new("form","OTP challenge","",[otpField])));
Check("password_named_otp_not_saved",!AuthPolicy.IsPassword(passwordField,new("form","Enter one-time code","",[new("username","Username",1,[]),passwordField],"_login")));
Check("username_classified",AuthPolicy.IsUser(new("username","Username",1,[])));
Check("blank_profile_has_no_private_defaults",new Config().Server==""&&new Config().TrueConfHost==""&&new Config().Rdp=="");
var fortinetUser=new AuthField("username","Username: ",1,[]);
var fortinetSecret=new AuthField("credential","Password: ",2,[]);
Check("fortinet_login_password_can_be_saved",AuthPolicy.IsPassword(fortinetSecret,new("form","","",[fortinetUser,fortinetSecret],"_login")));
Check("fortinet_html_challenge_never_saved",!AuthPolicy.IsPassword(fortinetSecret,new("form","","",[fortinetSecret],"unknown")));
Check("unknown_password_form_never_saved",!AuthPolicy.IsPassword(passwordField,new("form","","",[passwordField],"_challenge")));
Check("auth_trace_keeps_only_http_status",AuthPolicy.HttpEvent("HTTP/1.1 401 private-server-text password=example")=="http_401");
Check("auth_trace_accepts_http10",AuthPolicy.HttpEvent("HTTP/1.0 200 OK")=="http_200");
Check("auth_trace_rejects_non_status_secret",AuthPolicy.HttpEvent("Set-Cookie: SVPNCOOKIE=example")==null);
Check("auth_trace_rejects_invalid_status",AuthPolicy.HttpEvent("HTTP/1.1 40x secret")==null&&AuthPolicy.HttpEvent("HTTP/1.1 200secret")==null);
Check("html_answer_form_is_challenge",AuthPolicy.FormCategory(new("form","Answer:","",[fortinetSecret],"unknown"))=="challenge");
Check("auth_trace_category_never_contains_form_text",AuthPolicy.FormCategory(new("form","private-message","private-error",[fortinetUser,fortinetSecret],"private-form"))=="login");
var responseWait=new AuthResponseWait(1000);
Check("auth_waits_90_seconds_for_response",!responseWait.TryExpire(90999));
Check("auth_user_input_pauses_network_timeout",responseWait.BeginForm()&&!responseWait.TryExpire(500000));
responseWait.EndForm(500000);
Check("auth_response_deadline_restarts_after_input",!responseWait.TryExpire(589999)&&responseWait.TryExpire(590000));
int phantomForms=0;
for(int i=0;i<4;i++){if(responseWait.BeginForm())phantomForms++;responseWait.EndForm(600000+i*1000);}
Check("native_forms_after_timeout_are_not_shown",phantomForms==0&&responseWait.Expired);
Check("timeout_cancel_command_is_emitted_once",!responseWait.TryExpire(900000));
Check("openconnect_exit2_is_session_rejection",VpnExitError.Describe(2,false).Kind=="session_rejected");
Check("session_rejection_distinguishes_setup_from_disconnect",VpnExitError.Describe(2,false).Message.Contains("создании туннеля")&&!VpnExitError.Describe(2,true).Message.Contains("создании туннеля"));
Check("unknown_exit_does_not_invent_a_cause",VpnExitError.Describe(1,false).Kind=="client_stopped"&&VpnExitError.Describe(1,false).Message.Contains("не определена"));
Console.WriteLine(JsonSerializer.Serialize(new{Successful=results.Values.All(x=>x),Checks=results}));
return results.Values.All(x=>x)?0:1;

sealed class FakeUpdateHandler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> answer):HttpMessageHandler
{
 public string? Url {get;private set;}
 protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken){Url=request.RequestUri?.ToString();return answer(request,cancellationToken);}
}

sealed class StalledUpdateStream:Stream
{
 public override bool CanRead=>true;
 public override bool CanSeek=>false;
 public override bool CanWrite=>false;
 public override long Length=>throw new NotSupportedException();
 public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
 public override void Flush(){}
 public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
 public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)=>new(Wait(cancellationToken));
 private static async Task<int> Wait(CancellationToken token){await Task.Delay(Timeout.Infinite,token);return 0;}
 public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
 public override void SetLength(long value)=>throw new NotSupportedException();
 public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
}
