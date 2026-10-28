namespace FortiSplit.Work;

public sealed record AuthChoice(string Value,string Label);
public sealed record AuthField(string Name,string Label,int Type,AuthChoice[] Choices);
public sealed record AuthRequest(string Kind,string Message,string Error,AuthField[] Fields,string FormId="");
public sealed record AuthReply(bool Cancelled,Dictionary<string,string> Values);

public static class AuthPolicy
{
 public static bool IsUser(AuthField field) => field.Type==1 && new[]{"username","user","login"}.Contains(field.Name.ToLowerInvariant());
 public static bool IsPassword(AuthField field,AuthRequest request) => field.Type==2
  && request.FormId=="_login"&&request.Fields.Any(IsUser)
  && (new[]{"password","passwd"}.Contains(field.Name.ToLowerInvariant())
      || (field.Name=="credential"&&field.Label.StartsWith("Password",StringComparison.OrdinalIgnoreCase)))
  && !IsChallenge(request.Message+" "+field.Label);
 private static bool IsChallenge(string text) => new[]{"otp","token","one-time","verification code","однораз","2fa","challenge"}.Any(x=>text.Contains(x,StringComparison.OrdinalIgnoreCase));
 public static string Caption(AuthField field,AuthRequest request) => IsUser(field)?"Рабочий логин":IsPassword(field,request)?"Пароль":field.Type is 2 or 5?"Код подтверждения / ответ сервера":field.Label;
}
