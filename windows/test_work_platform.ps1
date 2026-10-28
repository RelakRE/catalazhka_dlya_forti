# Read-only contract check against the actual Windows cmdlet output.
$ErrorActionPreference='Stop'
$row=Get-NetIPInterface -AddressFamily IPv4 | Select-Object -First 1
if ($null -eq $row -or -not $row.PSObject.Properties['NlMtu']) { throw 'Get-NetIPInterface does not expose NlMtu' }
if ([uint64]$row.NlMtu -lt 576) { throw 'Unexpected MTU value' }
if (-not (Get-Command Set-NetIPInterface).Parameters.ContainsKey('NlMtuBytes')) { throw 'Missing MTU setter parameter' }
Write-Output 'PLATFORM_CHECK_PASSED: read NlMtu; setter parameter NlMtuBytes; network not modified'
