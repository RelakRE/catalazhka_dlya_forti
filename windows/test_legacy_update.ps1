param([Parameter(Mandatory)][string]$LegacyArchive,[Parameter(Mandatory)][string]$Archive)
$ErrorActionPreference='Stop'
# Run on a disposable Windows release runner. The released 1.2.7 binary uses the
# real LocalAppData and named UI mutex, so never run against an existing profile.
$appRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Forti Split Work'
if(Test-Path -LiteralPath $appRoot){throw 'The upgrade check requires a fresh Windows profile'}
if((Get-FileHash -LiteralPath $LegacyArchive).Hash -ne '24dec57825b791a918fd9b93e032d73a9c83a01c248c008b58df3cb883411863'){
 throw 'Unexpected 1.2.7 release archive'
}
$id=[guid]::NewGuid().ToString('N')
$originDir=Join-Path ([IO.Path]::GetTempPath()) "FortiSplit-1.2.7-$id"
Expand-Archive -LiteralPath $LegacyArchive -DestinationPath $originDir
$origin=Join-Path $originDir 'Forti Split.exe'
$updates=Join-Path $appRoot 'updates'
$version=Join-Path $updates "versions/$id"
$staging=New-Item -ItemType Directory -Path (Join-Path $updates "staging/$id") -Force
$links=New-Item -ItemType Directory -Path (Join-Path $updates 'links')
$settings=Join-Path $appRoot 'settings.json'
@{ConnectOnOpen=$false;User='sample.user'} | ConvertTo-Json | Set-Content -LiteralPath $settings -Encoding utf8
$settingsHash=(Get-FileHash -LiteralPath $settings).Hash

# Exercise the v1 ZIP allowlist and size limits before invoking the shipped
# helper at exactly the point where 1.2.7 has discarded the downloaded archive.
$checks=Join-Path $PSScriptRoot 'FortiSplit.Work.Checks/bin/Release/net10.0/FortiSplit.Work.Checks.dll'
dotnet $checks --extract-update $Archive $version
if($LASTEXITCODE -ne 0){throw 'The release ZIP could not be staged'}
$target=Join-Path $version 'Forti Split.exe'
$hash=(Get-FileHash -LiteralPath $target).Hash
@{OriginExe=$origin} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $version '.fortisplit-origin.json') -Encoding utf8
@{OriginExe=$origin;CurrentExe=$origin;TargetSha256=$hash;ParentId=[int]::MaxValue;ParentTicks=0} |
 ConvertTo-Json | Set-Content -LiteralPath (Join-Path $staging 'ticket.json') -Encoding utf8
$helper=Join-Path $staging 'updater.exe'
Copy-Item -LiteralPath $origin -Destination $helper
$ready=[Threading.EventWaitHandle]::new($false,'AutoReset',("Local\FortiSplitUpdateReady-"+$id))
$process=Start-Process -FilePath $helper -ArgumentList '--complete-update',$id -PassThru -WindowStyle Hidden
try{
 if(!$ready.WaitOne(10000)){throw '1.2.7 rejected the staged update'}
 if(!$process.WaitForExit(40000) -or $process.ExitCode -ne 0){throw '1.2.7 did not complete the update'}
 $saved=@(Get-ChildItem -LiteralPath $links -Filter '*.json')
 if($saved.Count -ne 1){throw 'Expected one committed launcher link'}
 $link=Get-Content -LiteralPath $saved[0].FullName -Raw | ConvertFrom-Json
 if($link.Pending -or $link.OriginExe -ne $origin -or $link.TargetExe -ne $target -or $link.TargetSha256 -ne $hash){
  throw '1.2.7 failed to commit the new executable'
 }
 if((Get-FileHash -LiteralPath $settings).Hash -ne $settingsHash){throw 'The upgrade changed the saved profile'}
}finally{
 if(!$process.HasExited){$process.Kill();$process.WaitForExit()}
 $process.Dispose();$ready.Dispose()
 Get-Process -Name 'Forti Split' -ErrorAction SilentlyContinue | Where-Object { $_.Path -in @($target,$origin) } |
  ForEach-Object { $_.Kill();$_.WaitForExit();$_.Dispose() }
}
