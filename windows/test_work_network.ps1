# Offline integration test: every network cmdlet is replaced by an in-memory fake.
$ErrorActionPreference='Stop'
$testRoot=Join-Path $PSScriptRoot ('build\network-check-'+[guid]::NewGuid().ToString('N'))
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sessionRoot=Join-Path $testRoot 'sessions'
$session=Join-Path $sessionRoot ($sid+'-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $session -Force | Out-Null
$journalDirectory=New-Item -ItemType Directory -Path (Join-Path $testRoot 'state')
function Enable-Hook($Path) {
 [IO.File]::WriteAllText((Join-Path $journalDirectory.FullName ([IO.Path]::GetFileName($Path)+'.live')),'')
}
$originalTemp=$env:TEMP;$originalTmp=$env:TMP
try {
 $env:TEMP=$env:TMP=$testRoot
 Add-Type -TypeDefinition @'
using System;
public static class FortiSplitNetworkGuard {
 public static string[] Addresses = new string[0];
 public static uint Index;
 public static bool FailNextShrink;
 public static void Replace(Guid session, uint index, string[] journaled, string[] desired) {
  if (FailNextShrink && desired.Length < Addresses.Length) {
   FailNextShrink = false;
   throw new InvalidOperationException("fake WFP commit failure");
  }
  Addresses = desired;
  Index = index;
 }
}
'@
} finally { $env:TEMP=$originalTemp;$env:TMP=$originalTmp }
Enable-Hook $session
$global:fortiTestroutes=@();$global:fortiTestrules=@();$global:fortiTestips=@();$global:fortiTestfailResolve=$false;$global:fortiTestfailRemove=$false;$global:fortiTestMissingNames=@()
$global:fortiTestadapter=[pscustomobject]@{ifIndex=77;InterfaceIndex=77;InterfaceGuid='test-guid';Name='FortiSplitWork';Status='Up';InterfaceDescription='Wintun'}
$global:fortiTestDnsCalls=0;$global:fortiTestCacheClears=0
$global:fortiTestDnsMap=@{};$global:fortiTestDnsIpv6=@{};$global:fortiTestAlias=$false;$global:fortiTestRouteEvents=@()
$global:fortiTestSlowName=$null;$global:fortiTestDnsNames=@()
$global:fortiTestFailDnsRule=$false;$global:fortiTestFailRemovePrefix=$null
$global:fortiTestBeforeRemoveRoute=$null
function global:Clear-DnsClientCache { [CmdletBinding()]param();$global:fortiTestCacheClears++ }
function global:Get-NetAdapter { param($InterfaceIndex,[switch]$IncludeHidden); $global:fortiTestadapter }
function global:Get-NetIPInterface { param($InterfaceIndex,$AddressFamily); [pscustomobject]@{NlMtu=1500} }
function global:Set-NetIPInterface { param($InterfaceIndex,$AddressFamily,$NlMtuBytes,$PolicyStore) }
function global:Get-NetIPAddress { param($InterfaceIndex,$AddressFamily); $global:fortiTestips }
function global:New-NetIPAddress { param($InterfaceIndex,$IPAddress,$PrefixLength,$PolicyStore);$global:fortiTestips+=@([pscustomobject]@{IPAddress=$IPAddress;InterfaceIndex=$InterfaceIndex}); }
function global:Remove-NetIPAddress { [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{$global:fortiTestips=@($global:fortiTestips|Where-Object IPAddress -ne $InputObject.IPAddress)} }
function global:Get-NetRoute { param($InterfaceIndex,$AddressFamily,$PolicyStore);$global:fortiTestroutes }
function global:New-NetRoute { param($InterfaceIndex,$DestinationPrefix,$NextHop,$RouteMetric,$PolicyStore);$global:fortiTestRouteEvents+=@('add:'+$DestinationPrefix);$global:fortiTestroutes+=@([pscustomobject]@{InterfaceIndex=$InterfaceIndex;DestinationPrefix=$DestinationPrefix;NextHop=$NextHop;RouteMetric=$RouteMetric}) }
function global:Remove-NetRoute { [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline=$true)]$InputObject);process{if($global:fortiTestfailRemove -or $InputObject.DestinationPrefix -eq $global:fortiTestFailRemovePrefix){throw 'fake removal failure'};if($global:fortiTestBeforeRemoveRoute){& $global:fortiTestBeforeRemoveRoute $InputObject};$global:fortiTestRouteEvents+=@('remove:'+$InputObject.DestinationPrefix);$global:fortiTestroutes=@($global:fortiTestroutes|Where-Object {$_.DestinationPrefix -ne $InputObject.DestinationPrefix -or $_.InterfaceIndex -ne $InputObject.InterfaceIndex})} }
function global:Get-DnsClientNrptRule { $global:fortiTestrules }
function global:Get-DnsClientNrptPolicy { param([switch]$Effective);throw 'Runtime effective-policy diagnostics must not run' }
function global:Add-DnsClientNrptRule { param($Namespace,$NameServers,$Comment,$DisplayName);if($global:fortiTestFailDnsRule){throw 'fake DNS rule failure'};$global:fortiTestrules+=@([pscustomobject]@{Name=[guid]::NewGuid().ToString();Namespace=$Namespace;NameServers=$NameServers;Comment=$Comment}) }
function global:Set-DnsClientNrptRule { param($Name,$Namespace,$NameServers);if($global:fortiTestFailDnsRule){throw 'fake DNS rule failure'};$rule=$global:fortiTestrules | Where-Object Name -eq $Name;$rule.Namespace=$Namespace;$rule.NameServers=$NameServers }
function global:Remove-DnsClientNrptRule { param($Name,[switch]$Force);$global:fortiTestrules=@($global:fortiTestrules|Where-Object Name -ne $Name) }
function global:Resolve-DnsName {
 [CmdletBinding()]param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$QuickTimeout,[switch]$TcpOnly)
 $global:fortiTestDnsCalls++
 $global:fortiTestDnsNames+=@($Name)
 if($Name -eq $global:fortiTestSlowName){Start-Sleep -Milliseconds 15100;throw 'fake DNS timeout'}
 if(!$Server){return [pscustomobject]@{Type=1;IPAddress='203.0.113.199'}}
 if($global:fortiTestfailResolve -or $global:fortiTestMissingNames -contains $Name){throw 'fake DNS failure'}
 if($global:fortiTestAlias){[pscustomobject]@{Type=5;NameHost='alias.example.com'}}
 $ips=@('198.51.100.80')
 if($global:fortiTestDnsMap.ContainsKey($Name)){$ips=@($global:fortiTestDnsMap[$Name])}
 foreach($ip in $ips){[pscustomobject]@{Type=1;IPAddress=$ip}}
 if($Type -eq 'A_AAAA' -and $global:fortiTestDnsIpv6.ContainsKey($Name)){
  foreach($ip in $global:fortiTestDnsIpv6[$Name]){[pscustomobject]@{Type=28;IPAddress=$ip}}
 }
}
function Assert($condition,$message){if(-not $condition){throw $message}}
& {
 @{Hosts=@('desktop.example.com','gateway.example.com','video.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $global:fortiTestDnsIpv6['desktop.example.com']='2001:db8::80'
 $env:reason='connect';$env:TUNIDX='77';$env:INTERNAL_IP4_ADDRESS='192.0.2.50';$env:INTERNAL_IP4_DNS='192.0.2.53 192.0.2.54';$env:INTERNAL_IP4_MTU='1392'
 $hooks=New-Item -ItemType Directory -Path (Join-Path $testRoot 'hooks')
 $network=Join-Path $hooks.FullName 'Network.ps1'
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'FortiSplit.Work\Network.ps1') -Destination $network
 # A configured address may coincide with the endpoint of OpenConnect's outer connection.
 $env:VPNGATEWAY='203.0.113.45'
 @{Hosts=@('203.0.113.45','203.0.113.46','shared.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $global:fortiTestDnsMap['shared.example.com']=@('203.0.113.45','198.51.100.81')
 & $network -Session $session -Mode Hook
 Assert (!(Test-Path (Join-Path $session 'network-hook-error.txt'))) 'A work address matching the VPN gateway aborted the hook'
 Assert ($global:fortiTestroutes.DestinationPrefix -contains '203.0.113.46/32') 'The other literal work address was not installed'
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Routes -contains '198.51.100.81/32') 'A matching DNS answer prevented setup for another work IP'
 Assert ($s.Routes -notcontains '203.0.113.45/32' -and $s.Guarded -notcontains '203.0.113.45') 'A work route or filter captured the VPN gateway'
 Assert ($s.GatewayConflicts -contains '203.0.113.45' -and $s.GatewayConflicts -contains 'shared.example.com') 'The UI did not receive the skipped work addresses'
 & $network -Session $session -Mode Retry -Generation $s.Generation
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.GatewayConflicts -contains 'shared.example.com') 'A DNS retry lost the skipped address warning'
 @{Hosts=@('203.0.113.45','203.0.113.47')}|ConvertTo-Json|Set-Content (Join-Path $session 'candidate-config.json')
 & $network -Session $session -Mode Apply -Generation $s.Generation
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Routes -contains '203.0.113.47/32' -and $s.GatewayConflicts -contains '203.0.113.45') 'Applying a mixed list rejected the safe work address'
 & $network -Session $session -Mode Cleanup
 $previousVpnDns=$env:INTERNAL_IP4_DNS
 $env:INTERNAL_IP4_DNS='2001:db8::53 203.0.113.45 192.0.2.53 192.0.2.53'
 & $network -Session $session -Mode Hook
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert (($s.Dns -join ',') -eq '192.0.2.53' -and $s.Routes -notcontains '203.0.113.45/32') 'Mixed DNS did not retain just the usable IPv4 resolver'
 & $network -Session $session -Mode Cleanup
 $env:INTERNAL_IP4_DNS='2001:db8::53'
 & $network -Session $session -Mode Hook
 Assert ($LASTEXITCODE -eq 1 -and $global:fortiTestroutes.Count -eq 0) 'An IPv4 session proceeded without an IPv4 DNS server'
 $env:INTERNAL_IP4_DNS=$previousVpnDns
 $env:VPNGATEWAY=''
 $global:fortiTestDnsMap.Clear()
 @{Hosts=@('desktop.example.com','gateway.example.com','video.example.com')}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 & $network -Session $session -Mode Hook
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'base_ready') 'Base tunnel not ready'
 Assert ($global:fortiTestroutes.Count -eq 2) 'Only DNS routes expected before resolver'
 Assert ($global:fortiTestrules.Count -eq 1 -and $global:fortiTestrules[0].Namespace -contains 'desktop.example.com') 'Exact work-name DNS rules must precede the first lookup'
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready') 'Resolution failed'
 Assert ($global:fortiTestroutes.Count -eq 3) 'Resolved address must be deduplicated'
 Assert ([FortiSplitNetworkGuard]::Addresses -contains '198.51.100.80') 'Resolved address must be guarded'
 Assert ([FortiSplitNetworkGuard]::Addresses -contains '2001:db8::80' -and $s.Guarded -contains '2001:db8::80') 'AAAA answer must be protected and journaled'
 Assert ($s.Routes -notcontains '2001:db8::80/32') 'IPv6 answer became an IPv4 tunnel route'
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
 Assert ([FortiSplitNetworkGuard]::Addresses.Count -eq 0) 'Owned filters were not removed after routes and DNS'
 $global:fortiTestDnsIpv6.Clear()
 Assert (-not (Test-Path (Join-Path $session 'network.json'))) 'State must disappear only after cleanup'
 & $network -Session $session -Mode Cleanup
 Assert ($global:fortiTestrules.Count -eq 1) 'Idempotent cleanup failed'
 # Losing the user session directory cannot erase the protected recovery journal.
 $orphanId=[guid]::NewGuid().ToString('N')
 $orphan=Join-Path $sessionRoot ($sid+'-'+$orphanId)
 New-Item -ItemType Directory -Path $orphan | Out-Null
 Enable-Hook $orphan
 Copy-Item -LiteralPath (Join-Path $session 'config.json') -Destination $orphan
 & $network -Session $orphan -Mode Hook
 Assert ($global:fortiTestroutes.Count -eq 2) 'Orphan setup did not install DNS routes'
 foreach($name in @('config.json','network.json')) { Remove-Item -LiteralPath (Join-Path $orphan $name) }
 Assert (@(Get-ChildItem -LiteralPath $orphan -Force).Count -eq 0) 'Unexpected files in orphan fixture'
 Remove-Item -LiteralPath $orphan
 $foreignOwner='S-1-0-0'
 $foreignSession=Join-Path $sessionRoot ($foreignOwner+'-'+$orphanId)
 $orphanJournal=Join-Path $journalDirectory.FullName ($foreignOwner+'-'+$orphanId+'.json')
 $orphanReceipt=Join-Path $journalDirectory.FullName ($foreignOwner+'-'+$orphanId+'.restored')
 Move-Item -LiteralPath (Join-Path $journalDirectory.FullName ($sid+'-'+$orphanId+'.json')) -Destination $orphanJournal
 $global:fortiTestfailRemove=$true
 & $network -Session $foreignSession -Mode Cleanup -OwnerSid $foreignOwner
 Assert ($LASTEXITCODE -eq 1 -and (Test-Path -LiteralPath $orphanJournal) -and !(Test-Path -LiteralPath $orphanReceipt)) 'Orphan cleanup failure changed the protected recovery record'
 $global:fortiTestfailRemove=$false
 & $network -Session $foreignSession -Mode Cleanup -OwnerSid $foreignOwner
 Assert ($global:fortiTestroutes.Count -eq 0 -and $global:fortiTestips.Count -eq 0) 'Protected journal could not recover routes or address'
 Assert ($global:fortiTestrules.Count -eq 1 -and $global:fortiTestrules[0].Name -eq 'foreign') 'Orphan cleanup changed foreign DNS policy'
 Assert (!(Test-Path -LiteralPath $orphanJournal) -and (Test-Path -LiteralPath $orphanReceipt)) 'Orphan recovery did not record confirmed cleanup'
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
 $global:fortiTestadapter.Name='Renamed adapter'
 & $network -Session $session -Mode Cleanup
 Assert (-not (Test-Path (Join-Path $session 'network.json'))) 'Cleanup retry failed'
 Assert ($global:fortiTestroutes.Count -eq 0 -and $global:fortiTestips.Count -eq 0) 'Renamed adapter retained network settings'
 Assert (@(Get-ChildItem -LiteralPath $journalDirectory.FullName -Filter '*.json').Count -eq 0) 'Privileged journal retained after cleanup'
 $global:fortiTestadapter.Name='FortiSplitWork'
 # A user-readable state copy cannot authorize route or DNS changes.
 & $network -Session $session -Mode Hook
 $trustedJournal=Get-ChildItem -LiteralPath $journalDirectory.FullName -Filter '*.json'
 $trustedState=Get-Content -LiteralPath $trustedJournal.FullName -Raw
 Remove-Item -LiteralPath $trustedJournal.FullName
 $privateRule=$global:fortiTestrules | Where-Object Comment -Like 'FortiSplitWork-*'
 & $network -Session $session -Mode Cleanup
 Assert ((Test-Path (Join-Path $session 'network.json')) -and $global:fortiTestroutes.Count -gt 0) 'Cleanup trusted the user-readable state copy'
 Assert ($global:fortiTestrules.Name -contains $privateRule.Name) 'Cleanup removed DNS without a protected journal'
 Set-Content -LiteralPath $trustedJournal.FullName -Value $trustedState -Encoding UTF8
 & $network -Session $session -Mode Cleanup
 Assert (!(Test-Path (Join-Path $session 'network.json')) -and $global:fortiTestroutes.Count -eq 0) 'Protected journal was not recovered'
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
 $global:fortiTestMissingNames=@()
 $global:fortiTestDnsMap['desktop.example.com']=@('0.0.0.0','127.0.0.1')
 $global:fortiTestDnsMap['gateway.example.com']=@('169.254.10.20','198.51.100.80')
 & $network -Session $session -Mode Hook
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and $s.Unresolved -contains 'desktop.example.com') 'Invalid optional DNS replies blocked the tunnel'
 Assert ((($s.Resolved | Where-Object Host -eq 'gateway.example.com').Addresses -join ',') -eq '198.51.100.80') 'Invalid answer discarded a valid sibling'
 Assert ($global:fortiTestroutes.Count -eq 3 -and $s.Routes -contains '198.51.100.80/32') 'Only valid work IPs should be routed'
 & $network -Session $session -Mode Cleanup
 $global:fortiTestDnsMap=@{}
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
 # Domain names alone: a transient startup failure is retried, and CNAME records
 # without IPAddress must not discard the accompanying A record in StrictMode.
 @{Hosts=@('site.example.com','shared.example.com');OptionalHosts=@();DnsDomains=@()}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 & $network -Session $session -Mode Hook
 $global:fortiTestfailResolve=$true
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Unresolved.Count -eq 2 -and $global:fortiTestroutes.Count -eq 2) 'Startup DNS failure must retain the DNS bootstrap routes'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains 'site.example.com'}).Count -eq 1) 'Failed work name lost exact DNS policy'
 Assert ($s.DnsFailures.Count -gt 0) 'DNS failures were silently discarded'
 $global:fortiTestfailResolve=$false;$global:fortiTestAlias=$true
 & $network -Session $session -Mode Retry
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Unresolved.Count -eq 0 -and $s.Resolved.Count -eq 2 -and $global:fortiTestroutes.Count -eq 3) 'Retry did not recover names through a CNAME response'
 $before=$global:fortiTestDnsCalls
 & $network -Session $session -Mode Retry
 Assert ($global:fortiTestDnsCalls -eq $before) 'Retry queried already resolved names'
 # One name changes address; the old shared IP remains required by the other.
 $global:fortiTestDnsMap['site.example.com']=@('198.51.100.81','198.51.100.82')
 & $network -Session $session -Mode Resolve
 Assert ($global:fortiTestroutes.Count -eq 5) 'Not all A records routed, or shared address removed'
 @{Hosts=@('site.example.com');OptionalHosts=@();DnsDomains=@()}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 & $network -Session $session -Mode Resolve
 Assert (@($global:fortiTestroutes|Where-Object DestinationPrefix -eq '198.51.100.80/32').Count -eq 0) 'Removed name retained its unshared route'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains 'shared.example.com'}).Count -eq 0) 'Removed name retained DNS policy'
 $global:fortiTestfailResolve=$true
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Unresolved.Count -eq 1 -and $global:fortiTestroutes.Count -eq 4) 'Transient refresh failure removed a working route'
 $global:fortiTestfailResolve=$false;$global:fortiTestRouteEvents=@();$global:fortiTestDnsMap['site.example.com']='198.51.100.83'
 & $network -Session $session -Mode Retry
 Assert ($global:fortiTestroutes.Count -eq 3) 'Changed DNS answer left stale routes'
 Assert ([array]::IndexOf($global:fortiTestRouteEvents,'add:198.51.100.83/32') -lt [array]::IndexOf($global:fortiTestRouteEvents,'remove:198.51.100.81/32')) 'Old route removed before its replacement was installed'
 $previousRoutes=@($global:fortiTestroutes.DestinationPrefix | Sort-Object)
 $previousRules=@($global:fortiTestrules.Name | Sort-Object)
 $candidate=Join-Path $session 'candidate-config.json'
 $global:fortiTestDnsMap['new.example.com']='198.51.100.84'
 $global:fortiTestDnsIpv6['new.example.com']='2001:db8::84'
 @{Hosts=@('new.example.com')}|ConvertTo-Json|Set-Content $candidate
 $global:fortiTestFailDnsRule=$true
 & $network -Session $session -Mode Apply
 $global:fortiTestFailDnsRule=$false
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($LASTEXITCODE -eq 2 -and $s.Stage -eq 'ready') 'A rejected DNS change must preserve the ready tunnel'
 Assert (-not (Compare-Object $previousRules @($global:fortiTestrules.Name | Sort-Object))) 'DNS failure changed the previous rules'
 Assert (-not (Compare-Object $previousRoutes @($global:fortiTestroutes.DestinationPrefix | Sort-Object))) 'DNS failure changed the previous routes'
 Assert ((Get-Content (Join-Path $session 'config.json') -Raw|ConvertFrom-Json).Hosts -contains 'site.example.com') 'Rejected candidate changed session config'
 $generation=$s.Generation
 $global:fortiTestFailRemovePrefix='198.51.100.83/32'
 & $network -Session $session -Mode Apply -Generation $generation
 $global:fortiTestFailRemovePrefix=$null
 Assert ($LASTEXITCODE -eq 2) 'Route removal failure was not rolled back'
 Assert (@($global:fortiTestrules | Where-Object {$_.Namespace -contains 'site.example.com'}).Count -eq 1) 'Route rollback did not restore DNS policy'
 Assert (-not (Compare-Object $previousRoutes @($global:fortiTestroutes.DestinationPrefix | Sort-Object))) 'Route rollback left candidate changes'
 $previousFilters=[FortiSplitNetworkGuard]::Addresses
 [FortiSplitNetworkGuard]::FailNextShrink=$true
 & $network -Session $session -Mode Apply -Generation $generation
 Assert ($LASTEXITCODE -eq 2) 'A failed final WFP replacement must preserve the live session'
 Assert ((Get-Content (Join-Path $session 'config.json') -Raw|ConvertFrom-Json).Hosts -contains 'site.example.com') 'WFP failure committed the candidate config'
 Assert ((Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json).Stage -eq 'ready') 'WFP failure replaced the ready journal'
 Assert (-not (Compare-Object $previousFilters ([FortiSplitNetworkGuard]::Addresses))) 'WFP rollback did not restore old filters'
 Assert (-not (Compare-Object $previousRoutes @($global:fortiTestroutes.DestinationPrefix | Sort-Object))) 'WFP rollback did not restore old routes'
 Assert (@($global:fortiTestrules|Where-Object {$_.Namespace -contains 'site.example.com'}).Count -eq 1) 'WFP rollback did not restore old DNS policy'
 & $network -Session $session -Mode Apply -Generation $generation
 Assert ((Get-Content (Join-Path $session 'config.json') -Raw|ConvertFrom-Json).Hosts -contains 'new.example.com') 'Successful candidate did not become the active config'
 Assert ($global:fortiTestroutes.DestinationPrefix -contains '198.51.100.84/32') 'Successful candidate did not install its route'
 Assert ([FortiSplitNetworkGuard]::Addresses -notcontains '198.51.100.83') 'An explicitly replaced work address remained blocked'
 Assert ([FortiSplitNetworkGuard]::Addresses -contains '2001:db8::84') 'An explicitly applied IPv6 destination was not blocked'
 $names=@(1..16 | ForEach-Object { "service$_.example.com" })
 foreach ($row in 1..16) {
  $global:fortiTestDnsMap["service$row.example.com"]=@(1..16 | ForEach-Object {"192.0.2.$((($row-1)*16+$_-1)%256)"})
 }
 # Use distinct ranges including the other documentation subnets for two rows.
 $global:fortiTestDnsMap['service4.example.com']=@(1..16 | ForEach-Object {"198.51.100.$_"})
 $global:fortiTestDnsMap['service16.example.com']=@(1..16 | ForEach-Object {"203.0.113.$_"})
 @{Hosts=$names}|ConvertTo-Json|Set-Content $candidate
 $global:fortiTestRouteEvents=@()
 & $network -Session $session -Mode Apply
 Assert ($LASTEXITCODE -eq 2 -and $global:fortiTestRouteEvents.Count -eq 0) 'Route overflow mutated the live route table'
 $env:reason='attempt-reconnect'
 & $network -Session $session -Mode Hook
 Assert (Test-Path (Join-Path $session 'network-reconnecting')) 'Reconnect did not invalidate readiness'
 & $network -Session $session -Mode Apply -Generation $generation
 Assert ($LASTEXITCODE -eq 3 -and $global:fortiTestRouteEvents.Count -eq 0) 'Apply was not deferred during reconnect'
 $env:reason='reconnect'
 $env:INTERNAL_IP4_DNS=''
 & $network -Session $session -Mode Hook
 Assert ($LASTEXITCODE -ne 0 -and (Test-Path (Join-Path $session 'network-hook-error.txt'))) 'Reconnect failure was not recorded'
 $global:fortiTestRetainedRule=($global:fortiTestrules | Where-Object Comment -Like 'FortiSplitWork-*').Name
 $global:fortiTestBeforeRemoveRoute={ param($route)
  $ip=$route.DestinationPrefix.Split('/')[0]
  Assert ([FortiSplitNetworkGuard]::Addresses -contains $ip) 'Reconnect removed a route before protecting its destination'
  Assert ($global:fortiTestrules.Name -contains $global:fortiTestRetainedRule) 'Reconnect removed the DNS policy before replacement'
 }
 $env:INTERNAL_IP4_DNS='192.0.2.55 192.0.2.56'
 & $network -Session $session -Mode Hook
 $global:fortiTestBeforeRemoveRoute=$null
 $newRule=$global:fortiTestrules | Where-Object Name -eq $global:fortiTestRetainedRule
 Assert (($newRule.NameServers -join ',') -eq '192.0.2.55,192.0.2.56') 'Reconnect did not replace the VPN DNS servers in place'
 Assert ([FortiSplitNetworkGuard]::Addresses -contains '198.51.100.84') 'Reconnect unprotected a previously active work IP'
 Assert ([FortiSplitNetworkGuard]::Addresses -contains '2001:db8::84') 'Reconnect unprotected a previously seen IPv6 destination'
 Assert ((Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json).Stage -eq 'base_ready') 'Reconnect did not publish new bootstrap state'
 Assert (-not (Test-Path (Join-Path $session 'network-reconnecting'))) 'Reconnect marker remained after bootstrap'
 Assert (-not (Test-Path (Join-Path $session 'network-hook-error.txt'))) 'Stale reconnect error survived successful bootstrap'
 $global:fortiTestRouteEvents=@()
 & $network -Session $session -Mode Retry -Generation $generation
 Assert ($LASTEXITCODE -eq 3 -and $global:fortiTestRouteEvents.Count -eq 0) 'Retry ran against a superseded tunnel'
 $env:reason='connect'
 @{Hosts=@();OptionalHosts=@();DnsDomains=@()}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 & $network -Session $session -Mode Resolve
 Assert ($global:fortiTestroutes.Count -eq 2) 'Empty site list removed DNS routes or retained site routes'
 Assert ($global:fortiTestrules.Count -eq 1 -and $global:fortiTestrules[0].Name -eq 'foreign') 'Site refresh modified foreign DNS policy'
 & $network -Session $session -Mode Cleanup
 Assert ($global:fortiTestroutes.Count -eq 0 -and $global:fortiTestips.Count -eq 0) 'Dynamic routes were not recoverable'
 @{Hosts=@('slow.example.com','fast.example.com');OptionalHosts=@()}|ConvertTo-Json|Set-Content (Join-Path $session 'config.json')
 $global:fortiTestSlowName='slow.example.com'
 $global:fortiTestDnsNames=@()
 & $network -Session $session -Mode Hook
 & $network -Session $session -Mode Resolve
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert ($s.Stage -eq 'ready' -and ($s.Deferred -join ',') -eq 'fast.example.com') 'The deadline must defer names never queried'
 & $network -Session $session -Mode Continue -Generation $s.Generation
 $s=Get-Content (Join-Path $session 'network.json') -Raw|ConvertFrom-Json
 Assert (($global:fortiTestDnsNames -join ',') -eq 'slow.example.com,fast.example.com') 'Continuation spent its budget on a name already tried'
 Assert ($s.Deferred.Count -eq 0 -and ($s.Unresolved -join ',') -eq 'slow.example.com' -and $s.Routes -contains '198.51.100.80/32') 'Continuation failed to install the late route'
 Remove-Item -LiteralPath (Join-Path $journalDirectory.FullName ([IO.Path]::GetFileName($session)+'.live'))
 & $network -Session $session -Mode Cleanup
 & $network -Session $session -Mode Hook
 Assert ($global:fortiTestroutes.Count -eq 0 -and [FortiSplitNetworkGuard]::Addresses.Count -eq 0) 'A delayed hook reinstalled settings after shutdown'
 Write-Output 'NETWORK_CHECKS_PASSED: hook, deferred DNS, route deduplication, no default route, ownership, cleanup, idempotence'
}
# Expected failure cases above set LASTEXITCODE. Reaching here means every assertion passed.
$global:LASTEXITCODE=0
