param([string]$Destination=(Join-Path $PSScriptRoot 'public-repo'))
$ErrorActionPreference='Stop'
$Destination=[IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $Destination) { throw 'Export destination already exists. Use a new directory.' }
New-Item -ItemType Directory -Path $Destination | Out-Null
$files=@('README.md','SECURITY.md','THIRD-PARTY.md','REVIEW.md','AGENTS.md','.gitignore','global.json','profile.example.json','run-forti-split.cmd','prepare.cmd','prepare-work.ps1','export-public.ps1','audit_public.py','test_windows_work.py','test_public_audit.py','test_work_network.ps1','test_work_platform.ps1','test_work_native.ps1','test-work.ps1','TESTING.md','build-release.ps1','release_notes.py','RELEASE-NOTES.md')
foreach ($name in $files) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $Destination $name) }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Sigstore-LICENSE.txt') -Destination $Destination
foreach ($project in @('FortiSplit.Work','FortiSplit.Work.Checks')) {
 $target=Join-Path $Destination $project
 New-Item -ItemType Directory -Path $target -Force | Out-Null
 foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $project) -File | Where-Object Extension -In @('.cs','.csproj','.ps1','.js','.ico')) { Copy-Item -LiteralPath $file.FullName -Destination $target }
}
Write-Output 'Public source exported. Run audit_public.py before publication. No Git operation was performed.'
