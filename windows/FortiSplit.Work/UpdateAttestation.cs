using System.Text;
using Sigstore;

namespace FortiSplit.Work;

internal static class UpdateAttestation
{
 private const string Repository="https://github.com/RelakRE/catalazhka_dlya_forti";
 private const string Main="refs/heads/main";
 private static readonly SigstoreVerifier Verifier=new();
 private static readonly VerificationPolicy Policy=new(){
  CertificateIdentity=new(){
   Issuer="https://token.actions.githubusercontent.com",
   SubjectAlternativeName=Repository+"/.github/workflows/windows-release.yml@"+Main,
   Extensions=new(){
    SourceRepositoryUri=Repository,SourceRepositoryIdentifier="1429614887",SourceRepositoryRef=Main,
    RunnerEnvironment="github-hosted"
   }
  }
 };

 internal static byte[] Read(string path)
 {
  using var input=File.OpenRead(path);
  if(input.Length is <=0 or >UpdateDownload.MaximumAttestationSize)throw new IOException("Неверный размер аттестации обновления.");
  byte[] proof=new byte[(int)input.Length];
  input.ReadExactly(proof);
  return proof;
 }

 internal static async Task Verify(Stream archive,byte[] proof,CancellationToken cancellation)
 {
  if(proof.Length is <=0 or >UpdateDownload.MaximumAttestationSize)throw new IOException("Неверный размер аттестации обновления.");
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
  timeout.CancelAfter(TimeSpan.FromSeconds(8));
  try{
   var bundle=SigstoreBundle.Deserialize(Encoding.UTF8.GetString(proof));
   var (valid,result)=await Verifier.TryVerifyStreamAsync(archive,bundle,Policy,timeout.Token).ConfigureAwait(false);
   if(valid&&result?.Statement?.PredicateType=="https://slsa.dev/provenance/v1")return;
  }catch(Exception error) when(!cancellation.IsCancellationRequested){
   throw new IOException("Не удалось проверить происхождение обновления в GitHub Actions.",error);
  }
  cancellation.ThrowIfCancellationRequested();
  throw new IOException("GitHub Actions не подтвердил происхождение обновления.");
 }
}
