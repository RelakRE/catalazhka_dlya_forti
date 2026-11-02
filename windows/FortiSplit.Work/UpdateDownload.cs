using System.Net;
using System.Net.Http;
using System.Security.Cryptography;

namespace FortiSplit.Work;

internal static class UpdateDownload
{
 private static bool Allowed(Uri uri)=>uri.Scheme==Uri.UriSchemeHttps&&uri.Port==443&&uri.UserInfo.Length==0&&
  uri.Fragment.Length==0&&new[]{"github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"}.Contains(uri.Host,StringComparer.OrdinalIgnoreCase);

 internal static async Task Download(UpdateCandidate release,string destination,CancellationToken cancellation,HttpMessageHandler? testHandler=null)
 {
  if(!release.CanInstall)throw new IOException("Выпуск не содержит проверяемого архива.");
  string v=$"{release.Version.Major}.{release.Version.Minor}.{release.Version.Build}";
  var url=new Uri($"https://github.com/RelakRE/catalazhka_dlya_forti/releases/download/windows-v{v}/Forti-Split-{v}-Windows-x64.zip");
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromMinutes(5));
  using var client=new HttpClient(testHandler??new HttpClientHandler{AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
  client.DefaultRequestHeaders.UserAgent.ParseAdd("FortiSplit-Update/1.0");
  HttpResponseMessage? response=null;
  try{
   for(int hop=0;hop<5;hop++){
    if(!Allowed(url))throw new IOException("Недопустимый адрес загрузки.");
    response=await client.GetAsync(url,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
    if(response.StatusCode is HttpStatusCode.Moved or HttpStatusCode.Redirect or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect){
     Uri next=response.Headers.Location??throw new IOException("Неверный адрес загрузки.");
     url=next.IsAbsoluteUri?next:new Uri(url,next);response.Dispose();response=null;continue;
    }
    break;
   }
   if(response is null)throw new IOException("Слишком много перенаправлений.");
   response.EnsureSuccessStatusCode();
   if(response.Content.Headers.ContentLength is long announced&&announced!=release.Size)throw new IOException("Размер обновления не совпадает.");
   await using var input=await response.Content.ReadAsStreamAsync(timeout.Token);
   await using var output=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None,81920,true);
   using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);byte[] buffer=new byte[81920];long total=0;int count;
   while((count=await input.ReadAsync(buffer,timeout.Token))>0){total+=count;if(total>release.Size)throw new IOException("Размер обновления превышен.");hash.AppendData(buffer,0,count);await output.WriteAsync(buffer.AsMemory(0,count),timeout.Token);}
   await output.FlushAsync(timeout.Token);
   if(total!=release.Size||!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(),Convert.FromHexString(release.Sha256)))throw new IOException("Не удалось проверить архив обновления.");
  }finally{response?.Dispose();}
 }
}
