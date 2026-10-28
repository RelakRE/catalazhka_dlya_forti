param([string]$SourceCommit='local')
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$output=Join-Path $PSScriptRoot 'build\release\Forti-Split-1.2.3-Windows-x64'
$assets=Join-Path $PSScriptRoot 'build\release-assets\1.2.3'
if(Test-Path -LiteralPath $output){throw 'Release output exists; use a clean checkout.'}
New-Item -ItemType Directory -Path $assets -Force | Out-Null
dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release -o $output
if($LASTEXITCODE -ne 0){throw 'Publish failed'}
Rename-Item -LiteralPath (Join-Path $output 'FortiSplit.exe') -NewName 'Forti Split.exe'
Copy-Item profile.example.json,SECURITY.md,THIRD-PARTY.md -Destination $output
$instructions=@'
FORTI SPLIT 1.2.3 — WINDOWS x64 (PREVIEW)

Распакуйте весь архив в отдельную папку и откройте «Forti Split.exe».
При первом запуске нужен интернет: приложение загрузит официальные VPN-компоненты
с GitLab OpenConnect, GitHub 7-Zip, 7-zip.org и wintun.net. SHA256 проверяется
перед использованием. Подготовка выполняется в окне приложения без консоли.
Папка приложения должна быть доступна для записи. Не запускайте из ZIP-архива.

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

Выпуск предварительный, без подписи издателя. Автономные тесты не подтверждают
реальный вход в конкретный VPN, вход в RDP или видеозвонок TrueConf.
Если политика Windows запрещает запуск, обратитесь к администратору.

Исходники и проверки: https://github.com/RelakRE/catalazhka_dlya_forti
OpenConnect: https://www.infradead.org/openconnect/
Wintun: https://www.wintun.net/
7-Zip: https://www.7-zip.org/
'@
[IO.File]::WriteAllText((Join-Path $output 'ПРОЧИТАЙ МЕНЯ.txt'),$instructions,[Text.UTF8Encoding]::new($false))
$licenses=New-Item -ItemType Directory -Path (Join-Path $output 'licenses')
$dotnetRoot=Split-Path (Get-Command dotnet).Source
Get-ChildItem -LiteralPath $dotnetRoot -File | Where-Object Name -Match '(?i)license|notice' | Copy-Item -Destination $licenses
foreach($pack in @('microsoft.netcore.app.runtime.win-x64','microsoft.windowsdesktop.app.runtime.win-x64')){
 $packRoot=Join-Path $env:USERPROFILE ".nuget/packages/$pack"
 if(Test-Path -LiteralPath $packRoot){
  $target=New-Item -ItemType Directory -Path (Join-Path $licenses $pack)
  Get-ChildItem -LiteralPath $packRoot -Recurse -File | Where-Object Name -Match '(?i)license|notice' | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $target ($_.Directory.Name+'-'+$_.Name))}
 }
}
if(@(Get-ChildItem -LiteralPath $licenses -Recurse -File).Count -lt 2){throw 'Missing .NET licenses'}
$exe=Join-Path $output 'Forti Split.exe'
$version=(Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
if($version -notlike '1.2.3*'){throw 'Release version mismatch'}
$archive=Join-Path $assets 'Forti-Split-1.2.3-Windows-x64.zip'
# Archive the clean app before downloading any third-party binaries for tests.
Compress-Archive -Path (Join-Path $output '*') -DestinationPath $archive -CompressionLevel Optimal
$prepare=Start-Process -FilePath $exe -ArgumentList '--prepare-runtime' -PassThru -WindowStyle Hidden
if(!$prepare.WaitForExit(600000)){$prepare.Kill();throw 'Runtime preparation timeout'}
if($prepare.ExitCode -ne 0){throw 'Official runtime preparation failed'}
$report=Join-Path $assets 'WINDOWS-VALIDATION.json'
$test=Start-Process -FilePath $exe -ArgumentList @('--self-test',('"'+$report+'"')) -PassThru -WindowStyle Hidden
if(!$test.WaitForExit(60000)){$test.Kill();throw 'Offline self-test timeout'}
if($test.ExitCode -ne 0){throw 'Native offline self-tests failed'}
$validation=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
if(!$validation.Successful){throw 'Incomplete self-test evidence'}
$runtime=& (Join-Path $output 'client\openconnect.exe') --version 2>$null
if($LASTEXITCODE -ne 0 -or ($runtime -join '') -notmatch 'v9\.21'){throw 'Unexpected OpenConnect version'}
$validation | Add-Member -NotePropertyName SourceCommit -NotePropertyValue $SourceCommit
$validation | Add-Member -NotePropertyName Version -NotePropertyValue '1.2.3'
$validation | Add-Member -NotePropertyName Runtime -NotePropertyValue 'OpenConnect 9.21; Wintun 0.14.1; upstream downloads verified with SHA256'
$validation | Add-Member -NotePropertyName RuntimeBundled -NotePropertyValue $false
$validation | Add-Member -NotePropertyName RealVpnAcceptance -NotePropertyValue 'not_run'
$validation | Add-Member -NotePropertyName Signed -NotePropertyValue $false
$validation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $report -Encoding utf8
$hashes=Get-ChildItem -LiteralPath $assets -File | Where-Object Name -Ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object {(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.Name}
[IO.File]::WriteAllText((Join-Path $assets 'SHA256SUMS.txt'),($hashes -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
Write-Output 'Windows release built and tested without connecting VPN.'
