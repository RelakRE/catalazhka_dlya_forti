using FortiSplit.Work;
using System.Text.Json;
var results=new Dictionary<string,bool>();
void Check(string name,bool condition)=>results.Add(name,condition);
void Reject(string name,Action action){try{action();Check(name,false);}catch(Exception){Check(name,true);}}
foreach(string host in new[]{"desktop.example.com","gateway.example.com","video.example.com","192.0.2.3"}){Config.Host(host);Check("host_"+host,true);}
foreach(string host in new[]{"localhost","127.0.0.1","0.0.0.0","224.0.0.1","169.254.1.1","::1","a.com & calc.exe","a..com","http://a.com","a.com\r\n","-a.com","a-.com"})Reject("reject_"+host,()=>Config.Host(host));
var config=new Config{Server="https://vpn.example.com",AutoRdp=false,AutoTrueConf=false};
config.PrepareRdp("full address:s:desktop.example.com\ngatewayhostname:s:gateway.example.com\ngatewayusagemethod:i:2\ngatewayprofileusagemethod:i:1");
Check("gateway_probe",config.ProbeHost=="gateway.example.com"&&config.ProbePort==443);
Check("rdp_and_gateway_routes",config.Hosts.SequenceEqual(new[]{"desktop.example.com","gateway.example.com"}));
config.PrepareRdp("full address:s:192.0.2.4:3390\ngatewayusagemethod:i:0");Check("direct_rdp_port",config.ProbePort==3390&&config.ProbeHost=="192.0.2.4");
Reject("rdp_command_rejected",()=>config.PrepareRdp("full address:s:foo & calc.exe"));
Reject("system_gateway_rejected",()=>config.PrepareRdp("full address:s:a.example\ngatewayhostname:s:b.example\ngatewayusagemethod:i:2\ngatewayprofileusagemethod:i:0"));
foreach(string url in new[]{"http://vpn.example","https://a:b@vpn.example","https://vpn.example/?secret=1","https://vpn.example/#x"})Reject("server_"+url,()=>new Config{Server=url,AutoRdp=false}.Validate());
Check("ready_only_launch",LaunchGate.CanLaunch(new("connected","ok",true),true));
Check("no_launch_during_auth",!LaunchGate.CanLaunch(new("authenticating","wait",true),true));
Check("no_stale_launch",!LaunchGate.CanLaunch(new("connected","ok",true),false));
Check("no_launch_without_ready",!LaunchGate.CanLaunch(new("connected","wait",false),true));
Check("config_has_no_auth_secrets",!JsonSerializer.Serialize(new Config()).Contains("\"Password\"",StringComparison.Ordinal));
string fakeExe=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N")+".exe");
try {
 File.WriteAllBytes(fakeExe,[]);
 var manualTc=new Config{Server="https://vpn.example.com",AutoRdp=false,AutoTrueConf=false,TrueConf=fakeExe,TrueConfHost="video.example.com",TrueConfFallback="192.0.2.20"};
 manualTc.PrepareRdp("full address:s:desktop.example.com");
 Check("manual_trueconf_keeps_vpn_routes",manualTc.Hosts.Contains(manualTc.TrueConfHost)&&manualTc.Hosts.Contains(manualTc.TrueConfFallback));
} finally {File.Delete(fakeExe);}
var loginProfile=new Config{User="sample.user",RememberPassword=true};
var restoredProfile=JsonSerializer.Deserialize<Config>(JsonSerializer.Serialize(loginProfile))!;
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
Console.WriteLine(JsonSerializer.Serialize(new{Successful=results.Values.All(x=>x),Checks=results}));
return results.Values.All(x=>x)?0:1;
