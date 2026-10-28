param([string]$ClientDirectory)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$dotnet=Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
$output=Join-Path $PSScriptRoot 'build\FortiSplit-1.2.4'
if ($ClientDirectory) {
 New-Item -ItemType Directory -Path (Join-Path $output 'client') -Force | Out-Null
 foreach ($file in Get-ChildItem -LiteralPath $ClientDirectory -File | Where-Object Extension -In @('.exe','.dll','.txt')) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $output 'client') -Force }
}
& $dotnet restore FortiSplit.Work/FortiSplit.Work.csproj
if ($LASTEXITCODE -ne 0) { throw 'Restore failed' }
& $dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release --no-restore -o $output
if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
& $dotnet run --project FortiSplit.Work.Checks -c Release
if ($LASTEXITCODE -ne 0) { throw 'C# checks failed' }
& (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -File (Join-Path $PSScriptRoot 'test_work_network.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Network simulation failed' }
Write-Host 'Build ready. Runtime required in client/. Setup did not connect VPN.'
