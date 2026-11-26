using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;

namespace FortiSplit.Work;

internal static class UpdateDownload
{
 private static readonly string? PublisherKey=typeof(UpdateDownload).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
  .SingleOrDefault(attribute=>attribute.Key=="FortiSplitUpdatePublicKey")?.Value;

 internal static bool CanInstall(UpdateCandidate? release)=>
  release is {HasVerifiableArchive:true,HasPublisherSignature:true}&&!string.IsNullOrEmpty(PublisherKey);

 internal static bool VerifyPublisher(string publicKey,string digest,ReadOnlySpan<byte> signature)
 {
  using var rsa=RSA.Create();
  byte[] key=Convert.FromBase64String(publicKey);
  rsa.ImportSubjectPublicKeyInfo(key,out int read);
  return read==key.Length&&rsa.KeySize is >=3072 and <=4096&&signature.Length==rsa.KeySize/8&&
   rsa.VerifyHash(Convert.FromHexString(digest),signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pss);
 }

 private static bool Allowed(Uri uri)=>uri.Scheme==Uri.UriSchemeHttps&&uri.Port==443&&uri.UserInfo.Length==0&&
  uri.Fragment.Length==0&&new[]{"github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"}.Contains(uri.Host,StringComparer.OrdinalIgnoreCase);

 private static Uri Asset(UpdateCandidate release,string suffix=""){
  string v=$"{release.Version.Major}.{release.Version.Minor}.{release.Version.Build}";
  return new($"https://github.com/RelakRE/catalazhka_dlya_forti/releases/download/windows-v{v}/Forti-Split-{v}-Windows-x64.zip{suffix}");
 }

 private static HttpClient CreateClient(HttpMessageHandler? testHandler){
  var client=new HttpClient(testHandler??new HttpClientHandler{AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
  client.DefaultRequestHeaders.UserAgent.ParseAdd("FortiSplit-Update/1.0");return client;
 }

 private static async Task<HttpResponseMessage> Get(HttpClient client,Uri url,CancellationToken token){
  for(int hop=0;hop<5;hop++){
    if(!Allowed(url))throw new IOException("Недопустимый адрес загрузки.");
    var response=await client.GetAsync(url,HttpCompletionOption.ResponseHeadersRead,token);
    if(response.IsSuccessStatusCode)return response;
    using(response){
     if(response.StatusCode is not (HttpStatusCode.Moved or HttpStatusCode.Redirect or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect))response.EnsureSuccessStatusCode();
     Uri next=response.Headers.Location??throw new IOException("Неверный адрес загрузки.");
     url=next.IsAbsoluteUri?next:new Uri(url,next);
    }
  }
  throw new IOException("Слишком много перенаправлений.");
 }

 internal static async Task VerifyRelease(UpdateCandidate release,CancellationToken cancellation)
 {
  if(!CanInstall(release))throw new IOException("Для этого выпуска недоступно подписанное обновление.");
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(20));
  using var client=CreateClient(null);
  using var response=await Get(client,Asset(release,".sig"),timeout.Token);
  await using var input=await response.Content.ReadAsStreamAsync(timeout.Token);
  byte[] signature=new byte[513];int length=await input.ReadAtLeastAsync(signature,signature.Length,false,timeout.Token);
  if(length>512||!VerifyPublisher(PublisherKey!,release.Sha256,signature.AsSpan(0,length)))
   throw new IOException("Подпись издателя обновления не прошла проверку.");
 }

 internal static async Task Download(UpdateCandidate release,string destination,CancellationToken cancellation,HttpMessageHandler? testHandler=null)
 {
   if(!release.HasVerifiableArchive)throw new IOException("Выпуск не содержит проверяемого архива.");
   using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromMinutes(5));
   using var client=CreateClient(testHandler);
   using var response=await Get(client,Asset(release),timeout.Token);
   if(response.Content.Headers.ContentLength is long announced&&announced!=release.Size)throw new IOException("Размер обновления не совпадает.");
   await using var input=await response.Content.ReadAsStreamAsync(timeout.Token);
   await using var output=new FileStream(destination,FileMode.CreateNew,FileAccess.Write,FileShare.None,81920,true);
   using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);byte[] buffer=new byte[81920];long total=0;int count;
   while((count=await input.ReadAsync(buffer,timeout.Token))>0){total+=count;if(total>release.Size)throw new IOException("Размер обновления превышен.");hash.AppendData(buffer,0,count);await output.WriteAsync(buffer.AsMemory(0,count),timeout.Token);}
   await output.FlushAsync(timeout.Token);
   if(total!=release.Size||!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(),Convert.FromHexString(release.Sha256)))throw new IOException("Не удалось проверить архив обновления.");
 }
}
