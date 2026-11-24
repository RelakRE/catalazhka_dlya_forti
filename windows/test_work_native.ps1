param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$Report
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$reportPath = [IO.Path]::GetFullPath($Report)
if (Test-Path -LiteralPath $reportPath) { throw 'Native report path already exists' }

function Invoke-App([string[]]$Arguments, [int]$Timeout, [string]$Step) {
    $process = Start-Process -FilePath $exe -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    try {
        if (!$process.WaitForExit($Timeout * 1000)) {
            $process.Kill()
            throw "$Step timed out"
        }
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

if ((Invoke-App @('--prepare-runtime') 600 'First-run runtime preparation') -ne 0) {
    throw 'First-run runtime preparation failed'
}
$exitCode = Invoke-App @('--self-test', ('"' + $reportPath + '"')) 60 'Native offline checks'
if (!(Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw 'Native checks did not write a report' }
$validation = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if ($exitCode -ne 0 -or !$validation.Successful -or !$validation.NoVpnConnection) {
    Get-Content -LiteralPath $reportPath
    throw 'Native offline checks failed'
}
Write-Output "Native offline checks passed. Report at $reportPath"
