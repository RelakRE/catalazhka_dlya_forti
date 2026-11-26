using System.Text.Json;
using System.Text.RegularExpressions;

namespace FortiSplit.Work;

public sealed record UpdateCandidate(Version Version, string PageUrl, long AssetId = 0, string Sha256 = "", long Size = 0, bool HasPublisherSignature = false)
{
 public bool HasVerifiableArchive => AssetId>0 && Size>0 && Size<=200L*1024*1024 && Regex.IsMatch(Sha256,@"^[a-f0-9]{64}$",RegexOptions.CultureInvariant);
}

public static class UpdateCatalog
{
 private const string PageBase="https://github.com/RelakRE/catalazhka_dlya_forti/releases/tag/";
 private static readonly Regex Tag=new(@"^windows-v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$",RegexOptions.CultureInvariant);

 public static Version CurrentVersion(string value)
 {
  string numeric=value.Split('+')[0].Split('-')[0];
  if(!Regex.IsMatch(numeric,@"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$",RegexOptions.CultureInvariant)||!Version.TryParse(numeric,out var version))
   throw new ArgumentException("Не удалось определить текущую версию.");
  return version;
 }

 public static UpdateCandidate? FindNewer(string json,Version current)
 {
  using var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=32});
  if(document.RootElement.ValueKind!=JsonValueKind.Array)throw new FormatException("Неверный список выпусков.");
  UpdateCandidate? best=null;
  foreach(var release in document.RootElement.EnumerateArray()){
   if(release.ValueKind!=JsonValueKind.Object||!release.TryGetProperty("draft",out var draft)||draft.ValueKind!=JsonValueKind.False||
      !release.TryGetProperty("tag_name",out var tagElement)||tagElement.ValueKind!=JsonValueKind.String||
      !release.TryGetProperty("assets",out var assets)||assets.ValueKind!=JsonValueKind.Array)continue;
   string tag=tagElement.GetString()??"";var match=Tag.Match(tag);
   if(!match.Success||!Version.TryParse(tag[9..],out var version)||version<=current||(best is not null&&version<=best.Version))continue;
   string assetName=$"Forti-Split-{version.Major}.{version.Minor}.{version.Build}-Windows-x64.zip";
   bool hasSignature=assets.EnumerateArray().Any(asset=>IsUploaded(asset,assetName+".sig"));
   foreach(var asset in assets.EnumerateArray()){
    if(!IsUploaded(asset,assetName))continue;
    long id=asset.TryGetProperty("id",out var idValue)&&idValue.ValueKind==JsonValueKind.Number&&idValue.TryGetInt64(out long parsedId)?parsedId:0;
    long size=asset.TryGetProperty("size",out var sizeValue)&&sizeValue.ValueKind==JsonValueKind.Number&&sizeValue.TryGetInt64(out long parsedSize)?parsedSize:0;
    string digest=asset.TryGetProperty("digest",out var digestValue)&&digestValue.ValueKind==JsonValueKind.String?digestValue.GetString()??"":"";
    string hash=digest.StartsWith("sha256:",StringComparison.Ordinal)?digest[7..]:"";
    best=new(version,PageBase+tag,id,hash,size,hasSignature);break;
   }
  }
  return best;
 }

 private static bool IsUploaded(JsonElement asset,string name)=>asset.ValueKind==JsonValueKind.Object&&
  asset.TryGetProperty("name",out var assetName)&&assetName.ValueKind==JsonValueKind.String&&assetName.GetString()==name&&
  asset.TryGetProperty("state",out var state)&&state.ValueKind==JsonValueKind.String&&state.GetString()=="uploaded";
}
