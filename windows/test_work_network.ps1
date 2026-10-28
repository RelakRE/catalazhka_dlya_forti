# Offline integration test: every network cmdlet is replaced by an in-memory fake.
$ErrorActionPreference='Stop'
$originalLocalAppData=$env:LOCALAPPDATA
$testRoot=Join-Path $PSScriptRoot ('build\network-check-'+[guid]::NewGuid().ToString('N'))
$env:LOCALAPPDATA=$testRoot
$session=Join-Path $testRoot ('Forti Split Work\sessions\'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $session -Force | Out-Null
$global:fortiTestroutes=@();$global:fortiTestrules=@();$global:fortiTestips=@();$global:fortiTestfailResolve=$false;$global:fortiTestfailRemove=$false;$global:fortiTestMissingNames=@()
$global:fortiTestadapter=[pscustomobject]@{ifIndex=77;InterfaceIndex=77;InterfaceGuid='test-guid';Name='FortiSplitWork';Status='Up';InterfaceDescription='Wintun'}
$global:fortiTestDnsCalls=0;$global:fortiTestCacheClears=0
function global:Clear-DnsClientCache { [CmdletBinding()]param();$global:fortiTestCacheClears++ }
function global:Get-NetAdapter { param($InterfaceIndex,[switch]$IncludeHidden); $global:fortiTestadapter }
function global:Get-NetIPInterface { param($InterfaceIndex,$AddressFamily); [pscustomobject]@{NlMtu=1500} }
function global:Set-NetIPInterface { param($InterfaceIndex,$AddressFamily,$NlMtuBytes,$PolicyStore) }
function global:Get-NetIPAddress { param($InterfaceIndex,$AddressFamily); $global:fortiTestips }
function global:New-NetIPAddress { param($InterfaceIndex,$IPAddress,$PrefixLength,$PolicyStore);$global:fortiTestips+=@([pscustomobject]@{IPAddress=$IPAddress;InterfaceIndex=$InterfaceIndex}); }
function global:Remove-NetIPAddress { [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{$global:fortiTestips=@($global:fortiTestips|Where-Object IPAddress -ne $InputObject.IPAddress)} }
function global:Get-NetRoute { param($InterfaceIndex,$AddressFamily,$PolicyStore);$global:fortiTestroutes }
function global:New-NetRoute { param($InterfaceIndex,$DestinationPrefix,$NextHop,$RouteMetric,$PolicyStore);$global:fortiTestroutes+=@([pscustomobject]@{InterfaceIndex=$InterfaceIndex;DestinationPrefix=$DestinationPrefix;NextHop=$NextHop;RouteMetric=$RouteMetric}) }
function global:Remove-NetRoute { [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{if($global:fortiTestfailRemove){throw 'fake removal failure'};$global:fortiTestroutes=@($global:fortiTestroutes|Where-Object {$_.DestinationPrefix -ne $InputObject.DestinationPrefix -or $_.InterfaceIndex -ne $InputObject.InterfaceIndex})} }
function global:Get-DnsClientNrptRule { $global:fortiTestrules }
function global:Get-DnsClientNrptPolicy { param([switch]$Effective);throw 'Runtime effective-policy diagnostics must not run' }
function global:Add-DnsClientNrptRule { param($Namespace,$NameServers,$Comment,$DisplayName);$global:fortiTestrules+=@([pscustomobject]@{Name=[guid]::NewGuid().ToString();Namespace=$Namespace;Comment=$Comment}) }
function global:Remove-DnsClientNrptRule { param($Name,[switch]$Force);$global:fortiTestrules=@($global:fortiTestrules|Where-Object Name -ne $Name) }
function global:Resolve-DnsName { [CmdletBinding()]param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$QuickTimeout,[switch]$TcpOnly);$global:fortiTestDnsCalls++;if($global:fortiTestfailResolve -or $global:fortiTestMissingNames -contains $Name){throw 'fake DNS failure'};[pscustomobject]@{IPAddress='198.51.100.80'} }
function Assert($condition,$message){if(-not $condition){throw $message}}
try {
 @{Hosts=@('desktop.example.com','gateway.example.com','video.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $env:reason='connect';$env:TUNIDX='77';$env:INTERNAL_IP4_ADDRESS='192.0.2.50';$env:INTERNAL_IP4_DNS='192.0.2.53 192.0.2.54';$env:INTERNAL_IP4_MTU='1392'
 $network=Join-Path $PSScriptRoot 'FortiSplit.Work\Network.ps1'
 & $network -Session $session -Mode Hook
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'base_ready') 'Base tunnel not ready'
 Assert ($global:fortiTestroutes.Count -eq 2) 'Only DNS routes expected before resolver'
 Assert ($global:fortiTestrules.Count -eq 0) 'DNS rule must not be created in sync hook'
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready') 'Resolution failed'
 Assert ($global:fortiTestroutes.Count -eq 3) 'Resolved address must be deduplicated'
 # Re-applying explicit setup must not treat the app's own DNS policy as foreign.
 & $network -Session $session -Mode Resolve
 Assert ((Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json).Stage -eq 'ready') 'Self DNS policy blocked connection'
 $env:reason='disconnect'
 & $network -Session $session -Mode Hook
 Assert (Test-Path (Join-Path $session 'network.json')) 'Unexpected VPN disconnect must preserve manual recovery journal'
 Assert ($global:fortiTestroutes.Count -eq 3) 'Disconnect hook performed automatic recovery'
 $env:reason='connect'
 Assert (@($global:fortiTestroutes|Where-Object DestinationPrefix -eq '0.0.0.0/0').Count -eq 0) 'Unexpected internet default route'
 $global:fortiTestrules+=@([pscustomobject]@{Name='foreign';Namespace=@('other.example');Comment='other app'})
 & $network -Session $session -Mode Cleanup
 Assert ($global:fortiTestroutes.Count -eq 0 -and $global:fortiTestips.Count -eq 0) 'Owned settings not removed'
 Assert ($global:fortiTestrules.Count -eq 1 -and $global:fortiTestrules[0].Name -eq 'foreign') 'Foreign DNS removed'
 Assert (-not (Test-Path (Join-Path $session 'network.json'))) 'State must disappear only after cleanup'
 & $network -Session $session -Mode Cleanup
 Assert ($global:fortiTestrules.Count -eq 1) 'Idempotent cleanup failed'
 & $network -Session $session -Mode Hook
 $global:fortiTestfailResolve=$true
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Unresolved.Count -eq 3) 'DNS failure must not disconnect VPN'
 Assert (-not (Test-Path (Join-Path $session 'dns-report.json'))) 'Unrequested diagnostic report created'
 $global:fortiTestfailResolve=$false
 $global:fortiTestfailRemove=$true
 & $network -Session $session -Mode Cleanup
 Assert (Test-Path (Join-Path $session 'network.json')) 'Failed cleanup lost recovery journal'
 $global:fortiTestfailRemove=$false
 & $network -Session $session -Mode Cleanup
 Assert (-not (Test-Path (Join-Path $session 'network.json'))) 'Cleanup retry failed'
 # A target known only to RD Gateway must not block the gateway VPN route.
 @{Hosts=@('gateway.example.com');OptionalHosts=@('desktop.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $global:fortiTestMissingNames=@('desktop.example.com')
 & $network -Session $session -Mode Hook
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready') 'Gateway-only target DNS must not block readiness'
 Assert (@($s.Resolved|Where-Object Host -eq 'gateway.example.com').Count -eq 1) 'Gateway route missing'
 Assert (@($s.Resolved|Where-Object Host -eq 'desktop.example.com').Count -eq 0) 'Unresolved target must not get DNS policy'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains 'desktop.example.com'}).Count -eq 0) 'Unresolved optional target got NRPT rule'
 & $network -Session $session -Mode Cleanup
 # Neither an unknown gateway nor direct target blocks the VPN.
 $global:fortiTestMissingNames=@('desktop.example.com','gateway.example.com')
 & $network -Session $session -Mode Hook
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Unresolved.Count -eq 2) 'Unknown gateway must not disconnect VPN'
 & $network -Session $session -Mode Cleanup
 @{Hosts=@('desktop.example.com');OptionalHosts=@()}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 & $network -Session $session -Mode Hook
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Unresolved -contains 'desktop.example.com') 'Direct target name blocked VPN'
 & $network -Session $session -Mode Cleanup
 $global:fortiTestMissingNames=@()
 # WorkVPN-style bootstrap must work before the first DNS response, for any PC.
 @{Hosts=@('203.0.113.21','203.0.113.22','203.0.113.23');OptionalHosts=@('different-pc.corp.example.com','gateway.rdp.example.com');DnsDomains=@('corp.example.com','rdp.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $global:fortiTestfailResolve=$true
 $before=$global:fortiTestDnsCalls
 & $network -Session $session -Mode Hook
 Assert ($global:fortiTestDnsCalls -eq $before) 'Connect hook waited for DNS through its own tunnel'
 Assert ($global:fortiTestroutes.Count -eq 5) 'Bootstrap gateway IP routes missing before DNS'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains '.corp.example.com' -and $_.Namespace -contains '.rdp.example.com'}).Count -eq 1) 'Private domain DNS policy missing before lookup'
 Assert ($global:fortiTestCacheClears -gt 0) 'Negative DNS cache was not cleared'
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Unresolved.Count -eq 2) 'Unknown PC blocked bootstrap configuration'
 Assert ($global:fortiTestroutes.Count -eq 5) 'DNS failure lost bootstrap gateway routes'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains '.corp.example.com'}).Count -eq 1) 'DNS failure lost private-domain policy'
 & $network -Session $session -Mode Cleanup
 Assert ($global:fortiTestroutes.Count -eq 0) 'Bootstrap routes not cleaned'
 Assert ($global:fortiTestrules.Count -eq 1 -and $global:fortiTestrules[0].Name -eq 'foreign') 'Bootstrap cleanup touched foreign DNS'
 $global:fortiTestfailResolve=$false
 Write-Output 'NETWORK_CHECKS_PASSED: hook, deferred DNS, route deduplication, no default route, ownership, cleanup, idempotence'
} finally { $env:LOCALAPPDATA=$originalLocalAppData }
# Expected failure cases above set LASTEXITCODE. Reaching here means every assertion passed.
$global:LASTEXITCODE=0
