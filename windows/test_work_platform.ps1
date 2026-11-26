# Read-only contract check against the actual Windows cmdlet output.
$ErrorActionPreference='Stop'
$row=Get-NetIPInterface -AddressFamily IPv4 | Select-Object -First 1
if ($null -eq $row -or -not $row.PSObject.Properties['NlMtu']) { throw 'Get-NetIPInterface does not expose NlMtu' }
if ([uint64]$row.NlMtu -lt 576) { throw 'Unexpected MTU value' }
if (-not (Get-Command Set-NetIPInterface).Parameters.ContainsKey('NlMtuBytes')) { throw 'Missing MTU setter parameter' }
Add-Type -Path (Join-Path $PSScriptRoot 'FortiSplit.Work\NetworkGuard.cs')
if (![FortiSplitNetworkGuard]::LayoutIsSupported()) { throw 'Unexpected x64 WFP structure layout' }
Write-Output 'PLATFORM_CHECK_PASSED: MTU schema and WFP structure layout; network not modified'
