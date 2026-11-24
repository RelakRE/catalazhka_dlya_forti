param([switch]$SourceOnly)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $run = Join-Path $PSScriptRoot ('build/work-tests/' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $run -Force | Out-Null
    $export = Join-Path $run 'source-audit'
    ./export-public.ps1 -Destination $export
    python -B audit_public.py $export
    if ($LASTEXITCODE -ne 0) { throw 'Public export audit failed' }
    python -B -m unittest test_windows_work test_public_audit
    if ($LASTEXITCODE -ne 0) { throw 'Python source checks failed' }
    dotnet run --project FortiSplit.Work.Checks -c Release
    if ($LASTEXITCODE -ne 0) { throw '.NET model checks failed' }
    powershell.exe -NoProfile -File ./test_work_network.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Simulated network checks failed' }
    powershell.exe -NoProfile -File ./test_work_platform.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Native network schema check failed' }
    if (!$SourceOnly) {
        $publish = Join-Path $run 'app'
        dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release -o $publish
        if ($LASTEXITCODE -ne 0) { throw 'Windows publish failed' }
        ./test_work_native.ps1 -Executable (Join-Path $publish 'FortiSplit.exe') -Report (Join-Path $run 'WINDOWS-VALIDATION.json')
    }
} finally {
    Pop-Location
}
