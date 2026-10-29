namespace FortiSplit.Work;

public sealed record AuthChoice(string Value,string Label);
public sealed record AuthField(string Name,string Label,int Type,AuthChoice[] Choices);
public sealed record AuthRequest(string Kind,string Message,string Error,AuthField[] Fields,string FormId="",int Attempt=1);
public sealed record AuthReply(bool Cancelled,Dictionary<string,string> Values);

// A timeout terminates the attempt permanently. A subsequent native form
// callback must not restart its deadline or ask for another MFA response.
public sealed class AuthResponseWait
{
 private long deadline;
 private int expired;
 public AuthResponseWait(long now){deadline=now+90000;}
 public bool Expired=>Volatile.Read(ref expired)!=0;
 public bool TryExpire(long now){if(now<Volatile.Read(ref deadline))return false;return Interlocked.CompareExchange(ref expired,1,0)==0;}
 public bool BeginForm(){if(Expired)return false;Volatile.Write(ref deadline,long.MaxValue);return !Expired;}
 public void EndForm(long now){if(!Expired)Volatile.Write(ref deadline,now+90000);}
}

public static class AuthPolicy
{
 public static string FormCategory(AuthRequest request) => request.Fields.Any(IsUser)?"login":"challenge";
 // Only fixed event names and numeric HTTP status reach diagnostics. Never retain
 // server text, headers, form values, or the native printf arguments themselves.
 public static string? HttpEvent(string statusLine) {
  if(!(statusLine.StartsWith("HTTP/1.0 ",StringComparison.Ordinal)||statusLine.StartsWith("HTTP/1.1 ",StringComparison.Ordinal)))return null;
  if(statusLine.Length<12||statusLine[9] is <'1' or >'5'||statusLine[10] is <'0' or >'9'||statusLine[11] is <'0' or >'9')return null;
  if(statusLine.Length>12&&statusLine[12]!=' '&&statusLine[12]!='\r'&&statusLine[12]!='\n')return null;
  return "http_"+statusLine.Substring(9,3);
 }
 public static bool IsUser(AuthField field) => field.Type==1 && new[]{"username","user","login"}.Contains(field.Name.ToLowerInvariant());
 public static bool IsPassword(AuthField field,AuthRequest request) => field.Type==2
  && request.FormId=="_login"&&request.Fields.Any(IsUser)
  && (new[]{"password","passwd"}.Contains(field.Name.ToLowerInvariant())
      || (field.Name=="credential"&&field.Label.StartsWith("Password",StringComparison.OrdinalIgnoreCase)))
  && !IsChallenge(request.Message+" "+field.Label);
 private static bool IsChallenge(string text) => new[]{"otp","token","one-time","verification code","однораз","2fa","challenge"}.Any(x=>text.Contains(x,StringComparison.OrdinalIgnoreCase));
 public static string Caption(AuthField field,AuthRequest request) => IsUser(field)?"Рабочий логин":IsPassword(field,request)?"Пароль":field.Type is 2 or 5?"Код подтверждения / ответ сервера":field.Label;
}
