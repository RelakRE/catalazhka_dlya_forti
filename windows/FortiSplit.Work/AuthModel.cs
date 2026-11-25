namespace FortiSplit.Work;

public sealed record AuthChoice(string Value,string Label);
public sealed record AuthField(string Name,string Label,int Type,AuthChoice[] Choices);
public sealed record AuthRequest(string Kind,string Message,string Error,AuthField[] Fields,string FormId="",int Attempt=1);
public sealed record AuthReply(bool Cancelled,Dictionary<string,string> Values);

internal sealed record AuthFailure(string Kind,string Message);

internal sealed class AuthFormHistory
{
 private readonly Dictionary<string,int> counts=new();
 private readonly HashSet<(string Id,string Fields)> requestedForms=new();

 internal AuthFailure? Next(AuthRequest request,out int step)
 {
  string category=AuthPolicy.FormCategory(request);
  step=counts.GetValueOrDefault(category)+1;
  // OpenConnect reuses these IDs for HTML and tokeninfo challenges.
  bool reusableChallenge=category=="challenge" && request.FormId is ("" or "unknown" or "_challenge");
  if(!reusableChallenge && !requestedForms.Add((request.FormId,FieldKey(request))))
  {
   string fields=category=="login"?"логин и пароль":"код подтверждения или ответ";
   return new("auth_form_repeated",$"Сервер VPN повторно запросил {fields}. Причина отказа неизвестна. "+AuthPolicy.RetryLater);
  }
  if(step>6)
   return new("form_limit","VPN запросил слишком много шагов входа. Попытка остановлена.");
  counts[category]=step;
  return null;
 }

 private static string FieldKey(AuthRequest request) => string.Join('\0',request.Fields
  .OrderBy(field=>field.Name,StringComparer.Ordinal).Select(field=>$"{field.Type}{field.Name}"));
}

// A timeout terminates the attempt permanently. A subsequent native form
// callback must not restart its deadline or ask for another MFA response.
public sealed class AuthResponseWait
{
 internal const int CodeWaitSeconds=30;
 private const int StandardWaitMilliseconds=90000;
 private readonly object gate=new();
 private long deadline;
 private bool awaitingCode,expired,completed;
 private string? httpEvent;
 private AuthFailure? responseProblem;
 private AuthFailure? failure;
 public AuthResponseWait(long now){deadline=now+StandardWaitMilliseconds;}
 public bool Expired{get{lock(gate)return expired;}}
 internal AuthFailure? Failure{get{lock(gate)return failure;}}
 internal string? HttpEvent{get{lock(gate)return httpEvent;}}
 internal AuthFailure? ResponseProblem{get{lock(gate)return responseProblem;}}
 internal bool RecordHttpResponse(string evt){
  lock(gate){
   if(completed||failure is not null)return false;
   httpEvent=evt;
   responseProblem=null;
   failure=AuthPolicy.TerminalHttpFailure(evt);
   return true;
  }
 }
 internal bool RecordResponseProblem(AuthFailure problem){
  lock(gate){
   // Cancelling a blocked read after the deadline can itself emit a read error.
   if(completed||failure is not null)return false;
   responseProblem=problem;
   return true;
  }
 }
 public bool TryExpire(long now){
  lock(gate){
   if(completed||failure is not null||now<deadline)return false;
   expired=true;
   string status=httpEvent is null?"":$" Последний статус VPN — HTTP {httpEvent[5..]}.";
   failure=responseProblem??(awaitingCode
    ?new("auth_code_timeout",$"Тайм-аут ожидания ответа VPN после отправки кода ({CodeWaitSeconds} секунд)."+status)
    :new("server_timeout",$"Тайм-аут ожидания ответа VPN ({StandardWaitMilliseconds/1000} секунд)."+status));
   return true;
  }
 }
 public bool BeginForm(){lock(gate){if(completed||failure is not null)return false;deadline=long.MaxValue;return true;}}
 public void EndForm(long now,bool codeSubmitted=false){
  lock(gate){
   if(completed||failure is not null)return;
   awaitingCode=codeSubmitted;
   httpEvent=null;
   responseProblem=null;
   deadline=now+(codeSubmitted?CodeWaitSeconds*1000:StandardWaitMilliseconds);
  }
 }
 internal void Abort(AuthFailure error){lock(gate){if(!completed)failure??=error;}}
 internal AuthFailure? Complete(){lock(gate){completed=true;return failure;}}
}

public static class AuthPolicy
{
 internal const string RetryLater="Подождите около двух минут перед новой попыткой.";

 // OpenConnect 9.21 http.c. Inspect the fixed printf format only.
 internal static AuthFailure? ProgressFailure(string format) => format switch
 {
  "Error reading HTTP response: %s\n" or "Error reading HTTP response body\n" or
  "Error fetching chunk header\n" or "Error fetching HTTP response body\n" =>
   new("auth_response_read_failed","Не удалось прочитать ответ VPN. Проверьте сеть и подключитесь снова."),
  "Failed to parse HTTP response '%s'\n" =>
   new("auth_invalid_http_response","VPN вернул некорректный HTTP-ответ."),
  "Failed to open HTTPS connection to %s\n" =>
   new("auth_https_connection_failed","Не удалось установить HTTPS-соединение с VPN."),
  _=>null
 };

 internal static AuthFailure? ServerFailure(string? httpEvent,AuthRequest? form=null,string banner="")
 {
  if(httpEvent=="http_429")
   return TerminalHttpFailure(httpEvent);
  if(IsLockout(form?.Error??"")||IsLockout(form?.Message??"")||IsLockout(banner))
   return new("auth_login_blocked","Сервер VPN временно ограничил вход из-за большого числа попыток. "+RetryLater);
  if((CodeFailure(form?.Error??"")??CodeFailure(form?.Message??"")??CodeFailure(banner)) is { } codeFailure)
   return codeFailure;
  // OpenConnect can parse an HTML challenge from either HTTP 401 or HTTP 403.
  if(httpEvent=="http_403" && (form is not { FormId: "unknown", Fields.Length: >0 } || FormCategory(form)=="login"))
   return new("auth_access_denied","Сервер VPN отказал в доступе (HTTP 403). "+RetryLater+" Если отказ повторится, обратитесь в ИТ.");
  return TerminalHttpFailure(httpEvent);
 }

 internal static AuthFailure? TerminalHttpFailure(string? httpEvent)
 {
  if(httpEvent=="http_429")
   return new("auth_rate_limited","Сервер VPN ограничил частоту запросов (HTTP 429). "+RetryLater);
  if(httpEvent=="http_405")
   return new("auth_input_rejected","Сервер VPN отклонил данные входа (HTTP 405). "+RetryLater);
  if(httpEvent?.StartsWith("http_5",StringComparison.Ordinal)==true)
   return new("auth_server_error",$"Сбой на стороне VPN-сервера или шлюза (HTTP {httpEvent[5..]}). "+RetryLater);
  return null;
 }

 private static bool IsLockout(string text) => new[]{
  "too many bad login attempts","too many failed login attempts","too many login attempts","слишком много попыток входа"
 }.Any(phrase=>text.Contains(phrase,StringComparison.OrdinalIgnoreCase));

 private static AuthFailure? CodeFailure(string text)
 {
  text=text.TrimStart();
  foreach(string prefix in new[]{"error:","ошибка:"})
   if(text.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)){text=text[prefix.Length..].TrimStart();break;}
  if(new[]{"expired verification code","otp has expired","срок действия кода истёк"}
    .Any(phrase=>text.StartsWith(phrase,StringComparison.OrdinalIgnoreCase)))
   return new("auth_code_expired","Срок действия одноразового кода истёк. "+RetryLater);
  if(new[]{"invalid verification code","incorrect verification code","the verification code is invalid",
    "invalid otp","incorrect otp","invalid token code","incorrect token code","invalid one-time password",
    "неверный код подтверждения","неверный одноразовый код"
   }.Any(phrase=>text.StartsWith(phrase,StringComparison.OrdinalIgnoreCase)))
   return new("auth_code_rejected","Сервер VPN отклонил одноразовый код. "+RetryLater);
  return null;
 }

 internal static bool IsSubmittedCode(AuthRequest request,AuthReply reply)
 {
  if(request.Fields is not [var field]||FormCategory(request)!="challenge"||field.Type is not (1 or 2 or 5)||
    !reply.Values.TryGetValue(field.Name,out var value)||string.IsNullOrWhiteSpace(value))return false;
  return field.Type==5||field.Name.ToLowerInvariant() is "code" or "otp" or "tokencode" or "token_code"||
   field.Label.Trim().TrimEnd(':').ToLowerInvariant() is "code" or "код"||
   (request.FormId is "unknown" or "_challenge" && value.Length is >=6 and <=8 && value.All(char.IsAsciiDigit))||
   new[]{"one-time","verification code","security code","fortitoken","однораз","код подтверждения"}
    .Any(phrase=>(field.Label+" "+request.Message).Contains(phrase,StringComparison.OrdinalIgnoreCase));
 }

 public static string FormCategory(AuthRequest request)
 {
  // Custom HTML forms can call their username field "email" or use a gateway-specific name.
  bool hasLoginPair=request.Fields.Any(field=>field.Type==1) && request.Fields.Any(field=>
   field.Type==2 && field.Name.ToLowerInvariant() is "password" or "passwd" or "j_password");
  return request.Fields.Any(IsUser)||hasLoginPair?"login":"challenge";
 }
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
