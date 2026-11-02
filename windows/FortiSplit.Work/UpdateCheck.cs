using System.Net.Http;
using System.Text;

namespace FortiSplit.Work;

internal static class UpdateCheck
{
 private const string Releases="https://api.github.com/repos/RelakRE/catalazhka_dlya_forti/releases?per_page=100";
 private const int Limit=2*1024*1024;

 internal static async Task<UpdateCandidate?> FindNewer(string current,CancellationToken cancellation,HttpMessageHandler? testHandler=null,TimeSpan? testTimeout=null)
 {
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
  timeout.CancelAfter(testTimeout??TimeSpan.FromSeconds(10));
  using var client=new HttpClient(testHandler??new HttpClientHandler{AllowAutoRedirect=false}){Timeout=Timeout.InfiniteTimeSpan};
  client.DefaultRequestHeaders.UserAgent.ParseAdd("FortiSplit-UpdateCheck/1.0");
  client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
  client.DefaultRequestHeaders.Add("X-GitHub-Api-Version","2022-11-28");
  using var response=await client.GetAsync(Releases,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
  response.EnsureSuccessStatusCode();
  if(response.Content.Headers.ContentLength>Limit)throw new IOException("Ответ об обновлениях слишком большой.");
  await using var input=await response.Content.ReadAsStreamAsync(timeout.Token);
  using var data=new MemoryStream();byte[] buffer=new byte[8192];int count;
  while((count=await input.ReadAsync(buffer,timeout.Token))>0){if(data.Length+count>Limit)throw new IOException("Ответ об обновлениях слишком большой.");data.Write(buffer,0,count);}
  return UpdateCatalog.FindNewer(Encoding.UTF8.GetString(data.ToArray()),UpdateCatalog.CurrentVersion(current));
 }
}
