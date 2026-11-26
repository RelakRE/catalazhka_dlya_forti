[CmdletBinding(DefaultParameterSetName='Publish')]
param([string]$SourceCommit='local',
 [Parameter(ParameterSetName='Publish')][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$UpdateSigningThumbprint,
 [Parameter(Mandatory,ParameterSetName='Attested')][string]$AttestedPublishDirectory)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$project='FortiSplit.Work/FortiSplit.Work.csproj'
$projectVersion=dotnet msbuild $project -nologo -getProperty:Version | Select-Object -Last 1
if($LASTEXITCODE -ne 0 -or $projectVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+-preview$'){throw 'Expected a Windows preview version in the project'}
$releaseVersion=$projectVersion.Split('-')[0]
$packageName="Forti-Split-$releaseVersion-Windows-x64"
$assetDirectory="build/release-assets/$releaseVersion"
$output=Join-Path $PSScriptRoot "build/release/$packageName"
$assets=Join-Path $PSScriptRoot $assetDirectory
if(Test-Path -LiteralPath $output){throw 'Release output exists; use a clean checkout.'}
New-Item -ItemType Directory -Path $assets -Force | Out-Null
$publishOptions=@()
if($UpdateSigningThumbprint){
 $publisherCertificate=Get-Item -LiteralPath "Cert:\CurrentUser\My\$UpdateSigningThumbprint"
 $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($publisherCertificate)
 try{
  if(!$rsa -or $rsa.KeySize -lt 3072 -or $rsa.KeySize -gt 4096){throw 'Updates require a 3072–4096 bit RSA signing key'}
  $publishOptions+=('-p:UpdateSigningPublicKey='+[Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo()))
 }finally{if($rsa){$rsa.Dispose()}}
}
if($AttestedPublishDirectory){
 New-Item -ItemType Directory -Path $output | Out-Null
 foreach($name in @('FortiSplit.exe','network-hook.js','Network.ps1')){
  Copy-Item -LiteralPath (Join-Path $AttestedPublishDirectory $name) -Destination $output
 }
}else{
 dotnet publish $project -c Release -o $output @publishOptions
 if($LASTEXITCODE -ne 0){throw 'Publish failed'}
}
Rename-Item -LiteralPath (Join-Path $output 'FortiSplit.exe') -NewName 'Forti Split.exe'
Copy-Item profile.example.json,SECURITY.md,THIRD-PARTY.md -Destination $output
[IO.File]::WriteAllText((Join-Path $output 'fortisplit-update-v1.json'),'{"format":1,"ready_signal":true}',[Text.UTF8Encoding]::new($false))
$instructions=@"
FORTI SPLIT $releaseVersion — WINDOWS x64 (PREVIEW)

Распакуйте весь архив в отдельную папку и откройте «Forti Split.exe».
Для первого подключения нужен интернет. После подтверждения UAC сетевой компонент
загрузит официальные VPN-компоненты с GitLab OpenConnect, GitHub 7-Zip, 7-zip.org
и wintun.net, проверит SHA-256 и установит их в защищённую папку Program Files.

В настройках импортируйте свой приватный профиль или укажите VPN-сервер,
рабочий логин и локальный RDP-файл. Профили Mac и Windows различаются.
При необходимости включите автоматический запуск RDP и настройте TrueConf.
Пример профиля содержит только вымышленные адреса. Реальный профиль получите
по приватному каналу; не прикладывайте его к публичным Issues.

Перед подключением отключите FortiClient. Нажмите «Подключить» и разрешите
запуск сетевого компонента в запросе Windows. Логин, пароль и 2FA вводятся
в интерфейсе приложения. Пароль сохраняется только по выбранной галочке
в Windows Credential Manager. Пароль и 2FA не включаются в JSON-профиль.
Для завершения нажмите «Отключить» и дождитесь восстановления сети.

Выпуск предварительный. Для автообновления требуется подтверждение происхождения
архива. Автономные тесты не подтверждают реальный вход в VPN, RDP или TrueConf.
Если политика Windows запрещает запуск, обратитесь к администратору.

Исходники и проверки: https://github.com/RelakRE/catalazhka_dlya_forti
OpenConnect: https://www.infradead.org/openconnect/
Wintun: https://www.wintun.net/
7-Zip: https://www.7-zip.org/
"@
[IO.File]::WriteAllText((Join-Path $output 'ПРОЧИТАЙ МЕНЯ.txt'),$instructions,[Text.UTF8Encoding]::new($false))
$licenses=New-Item -ItemType Directory -Path (Join-Path $output 'licenses')
$dotnetRoot=Split-Path (Get-Command dotnet).Source
Get-ChildItem -LiteralPath $dotnetRoot -File | Where-Object Name -Match '(?i)license|notice' | Copy-Item -Destination $licenses
$packagesRoot=$env:NUGET_PACKAGES
if(!$packagesRoot){$packagesRoot=Join-Path $env:USERPROFILE '.nuget/packages'}
Copy-Item -LiteralPath 'Sigstore-LICENSE.txt' -Destination $licenses
$restore=Get-Content -LiteralPath 'FortiSplit.Work/obj/project.assets.json' -Raw | ConvertFrom-Json
foreach($name in @('sigstore','tuf','bouncycastle.cryptography')){
 $package=$restore.libraries.PSObject.Properties | Where-Object { $_.Name -like "$name/*" } | Select-Object -First 1
 if(!$package){throw "Missing restored dependency: $name"}
 $source=Join-Path $packagesRoot $package.Value.path
 $notices=@(Get-ChildItem -LiteralPath $source -File | Where-Object Name -Match '(?i)license|notice')
 if(!$notices.Count){throw "Missing dependency license notices: $name"}
 $target=New-Item -ItemType Directory -Path (Join-Path $licenses $name)
 $notices | Copy-Item -Destination $target
}
foreach($pack in @('microsoft.netcore.app.runtime.win-x64','microsoft.windowsdesktop.app.runtime.win-x64')){
 $packRoot=Join-Path $packagesRoot $pack
 if(Test-Path -LiteralPath $packRoot){
  $target=New-Item -ItemType Directory -Path (Join-Path $licenses $pack)
  Get-ChildItem -LiteralPath $packRoot -Recurse -File | Where-Object Name -Match '(?i)license|notice' | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $target ($_.Directory.Name+'-'+$_.Name))}
 }
}
if(@(Get-ChildItem -LiteralPath $licenses -Recurse -File).Count -lt 2){throw 'Missing .NET licenses'}
$exe=Join-Path $output 'Forti Split.exe'
if($AttestedPublishDirectory){
 Copy-Item -LiteralPath (Join-Path $AttestedPublishDirectory 'FortiSplit.exe.sigstore.json') -Destination $licenses
}elseif($UpdateSigningThumbprint){
 $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($publisherCertificate)
 try{
  $digest=[Convert]::FromHexString((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)
  [IO.File]::WriteAllBytes((Join-Path $licenses 'FortiSplit.exe.sig'),$rsa.SignHash($digest,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss))
 }finally{$rsa.Dispose()}
}
$builtVersion=(Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
if(($builtVersion -split '\+',2)[0] -cne $projectVersion){throw 'Release version mismatch'}
$archive=Join-Path $assets "$packageName.zip"
# Archive the clean app before downloading any third-party binaries for tests.
$packageFiles=@('Forti Split.exe','Network.ps1','network-hook.js','profile.example.json','SECURITY.md',
 'THIRD-PARTY.md','fortisplit-update-v1.json','ПРОЧИТАЙ МЕНЯ.txt','licenses')
$packageEntries=@(Get-ChildItem -LiteralPath $output -Force)
if(Compare-Object $packageFiles $packageEntries.Name){throw 'Unexpected release package contents'}
if(@(Get-ChildItem -LiteralPath $output -Force -Recurse | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count){
 throw 'Release package cannot contain links'
}
Compress-Archive -Path (Join-Path $output '*') -DestinationPath $archive -CompressionLevel Optimal
if($UpdateSigningThumbprint){
 $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($publisherCertificate)
 try{
  $digest=[Convert]::FromHexString((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash)
  $signature=$rsa.SignHash($digest,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pss)
  [IO.File]::WriteAllBytes([IO.Path]::GetFullPath("$archive.sig"),$signature)
 }finally{$rsa.Dispose()}
}
$report=Join-Path $assets 'WINDOWS-VALIDATION.json'
./test_work_native.ps1 -Executable $exe -Report $report
$validation=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
$runtime=& (Join-Path $output 'client\openconnect.exe') --version 2>$null
if($LASTEXITCODE -ne 0 -or ($runtime -join '') -notmatch 'v9\.21'){throw 'Unexpected OpenConnect version'}
$validation | Add-Member -NotePropertyName SourceCommit -NotePropertyValue $SourceCommit
$validation | Add-Member -NotePropertyName Version -NotePropertyValue $releaseVersion
$validation | Add-Member -NotePropertyName Runtime -NotePropertyValue 'OpenConnect 9.21; Wintun 0.14.1; upstream downloads verified with SHA256'
$validation | Add-Member -NotePropertyName RuntimeBundled -NotePropertyValue $false
$validation | Add-Member -NotePropertyName RealVpnAcceptance -NotePropertyValue 'not_run'
$validation | Add-Member -NotePropertyName Signed -NotePropertyValue $false
$validation | Add-Member -NotePropertyName UpdateArchiveSigned -NotePropertyValue ([bool]$UpdateSigningThumbprint)
$validation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $report -Encoding utf8
$hashes=Get-ChildItem -LiteralPath $assets -File | Where-Object Name -Ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object {(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.Name}
[IO.File]::WriteAllText((Join-Path $assets 'SHA256SUMS.txt'),($hashes -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
if($env:GITHUB_OUTPUT){
 @("version=$releaseVersion","assets=$assetDirectory") | Add-Content -LiteralPath $env:GITHUB_OUTPUT -Encoding utf8
}
Write-Output 'Windows release built and tested without connecting VPN.'
