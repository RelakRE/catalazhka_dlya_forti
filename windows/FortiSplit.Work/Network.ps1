param([ValidateSet('Hook','Resolve','Continue','Retry','Apply','Cleanup')][string]$Mode='Hook',[Parameter(Mandatory=$true)][string]$Session,[string]$Generation)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 3
$Session=[IO.Path]::GetFullPath($Session)
$root=Join-Path $env:LOCALAPPDATA 'Forti Split Work\sessions'
if ([IO.Path]::GetDirectoryName($Session) -ne $root -or [IO.Path]::GetFileName($Session) -notmatch '^[a-f0-9]{32}$') { throw 'Invalid session path' }
$sessionExists=Test-Path -LiteralPath $Session -PathType Container
if (!$sessionExists -and ($Mode -ne 'Cleanup' -or (Test-Path -LiteralPath $Session))) { throw 'Invalid session directory' }
for ($part=[IO.DirectoryInfo]::new($Session); $null -ne $part; $part=$part.Parent) {
 if ($part.Exists -and ($part.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse path refused' }
}
$statePath=Join-Path $Session 'network.json'
$reconnectingPath=Join-Path $Session 'network-reconnecting'
$hookErrorPath=Join-Path $Session 'network-hook-error.txt'
$activeConfigPath=Join-Path $Session 'config.json'
$routeLimit=256
$sessionId=[IO.Path]::GetFileName($Session)
$journalDirectory=Join-Path (Split-Path -Parent $PSScriptRoot) 'state'
$journalBase=Join-Path $journalDirectory (([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)+'-'+$sessionId)
$journalPath=$journalBase+'.json'
$hookLeasePath=$journalBase+'.live'
$tag='FortiSplitWork-'+[IO.Path]::GetFileName($Session)
$mutex=New-Object Threading.Mutex($false,'Global\FortiSplitWork-Network')
$locked=$false
function Save-State {
 # The privileged journal is authoritative. The UI reads a copy in its session.
 $json=$script:state | ConvertTo-Json -Depth 8
 $json | Set-Content -LiteralPath ($journalPath+'.tmp') -Encoding UTF8
 if ([IO.File]::Exists($journalPath)) {
  [IO.File]::Replace($journalPath+'.tmp',$journalPath,[NullString]::Value)
 } else {
  [IO.File]::Move($journalPath+'.tmp',$journalPath)
 }
 $tmp=$statePath+'.tmp'
 foreach ($p in @($statePath,$tmp)) { if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'State link refused' } }
 $json | Set-Content -LiteralPath $tmp -Encoding UTF8
 if ([IO.File]::Exists($statePath)) {
  [IO.File]::Replace($tmp,$statePath,[NullString]::Value)
 } else {
  [IO.File]::Move($tmp,$statePath)
 }
}
function Test-IPv4([string]$IP) {
 $parsed=$null
 if (-not [Net.IPAddress]::TryParse($IP,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -ne $IP) { return $false }
 $b=$parsed.GetAddressBytes()
 return $b[0] -gt 0 -and $b[0] -ne 127 -and $b[0] -lt 224 -and ($b[0] -ne 169 -or $b[1] -ne 254)
}
function Assert-IP([string]$IP) {
 if (!(Test-IPv4 $IP)) { throw 'Invalid IPv4 or scope' }
}
function Assert-Host([string]$HostName) {
 if ($HostName.Length -gt 253 -or $HostName -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { throw 'Invalid work host' }
 foreach ($label in $HostName.Split('.')) { if ($label.Length -gt 63 -or $label.StartsWith('-') -or $label.EndsWith('-')) { throw 'Invalid label' } }
}
function Read-State {
 if (-not (Test-Path -LiteralPath $journalPath)) { return $null }
 if ((Get-Item -LiteralPath $journalPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State link refused' }
 $s=Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
 # A replacement may journal both the old and new route sets until commit.
 if ($s.Tag -ne $tag -or $s.Index -le 0 -or $s.Routes.Count -gt (2*$routeLimit)) { throw 'Invalid recovery state' }
 Assert-IP $s.Address
 foreach ($prefix in $s.Routes) { if (-not $prefix.EndsWith('/32')) { throw 'Non-host recovery route' }; Assert-IP $prefix.Substring(0,$prefix.Length-3) }
 if($s.PSObject.Properties['Guarded']){
  if(@($s.Guarded).Count -gt 1024){throw 'Filter journal bound'}
  foreach($ip in $s.Guarded){Assert-IP $ip}
 }
 return $s
}
function Clear-Tunnel($s) {
 $adapter=@(Get-NetAdapter -IncludeHidden | Where-Object { [string]$_.InterfaceGuid -eq $s.Guid })
 if ($adapter.Count -gt 1) { throw 'Ambiguous tunnel identity' }
 $index=$s.Index
 if ($adapter.Count -eq 1) {
  $index=$adapter[0].ifIndex
  foreach ($prefix in $s.Routes) {
   foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $index -and $_.DestinationPrefix -eq $prefix -and $_.NextHop -eq $s.Address -and $_.RouteMetric -eq 1 })) { $route | Remove-NetRoute -Confirm:$false }
  }
  if ($s.AddedAddress) { foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $index -and $_.IPAddress -eq $s.Address })) { $ip | Remove-NetIPAddress -Confirm:$false } }
  if ($s.OriginalMtu -gt 0) { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -NlMtuBytes $s.OriginalMtu -PolicyStore ActiveStore }
 }
 $indices=@($s.Index,$index)
 if (@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $indices -contains $_.InterfaceIndex -and $s.Routes -contains $_.DestinationPrefix -and $_.NextHop -eq $s.Address -and $_.RouteMetric -eq 1 }).Count) { throw 'Route cleanup not confirmed' }
 if ($s.AddedAddress -and @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $indices -contains $_.InterfaceIndex -and $_.IPAddress -eq $s.Address }).Count) { throw 'IP cleanup not confirmed' }
}
function Set-PacketFilters([uint32]$Index,[string[]]$Journaled,[string[]]$Desired) {
 if (!('FortiSplitNetworkGuard' -as [type])) {
  # CodeDom must compile in a directory writable only by Administrators and SYSTEM.
  $previousTemp=$env:TEMP;$previousTmp=$env:TMP
  try {
   $env:TEMP=$env:TMP=$journalDirectory
   Add-Type -Path (Join-Path $PSScriptRoot 'NetworkGuard.cs')
  } finally { $env:TEMP=$previousTemp;$env:TMP=$previousTmp }
 }
 [FortiSplitNetworkGuard]::Replace([guid]$sessionId,$Index,$Journaled,$Desired)
}
function Get-Guarded($State) {
 if($State.PSObject.Properties['Guarded']){ $State.Guarded }
}
function Set-Guard([string[]]$Desired,[uint32]$Index) {
 $known=@(Get-Guarded $script:state)
 $journaled=@($known+$Desired|Sort-Object -Unique)
 if($journaled.Count -gt 1024){throw 'Filter journal bound'}
 if($script:state.PSObject.Properties['GuardIndex'] -and $script:state.GuardIndex -eq $Index -and
    $journaled.Count -eq $known.Count -and $journaled.Count -eq $Desired.Count){return}
 # Record the union before changing WFP so a crash can recover either set.
 $script:state | Add-Member -NotePropertyName Guarded -NotePropertyValue $journaled -Force
 Save-State
 Set-PacketFilters $Index $journaled $Desired
 $script:state.Guarded=$Desired
 $script:state | Add-Member -NotePropertyName GuardIndex -NotePropertyValue $Index -Force
 Save-State
}
function Cleanup {
 $s=Read-State
 if ($null -eq $s) { return }
 Clear-Tunnel $s
 foreach ($rule in @(Get-DnsClientNrptRule | Where-Object Comment -eq $tag)) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
 if (@(Get-DnsClientNrptRule | Where-Object Comment -eq $tag).Count) { throw 'DNS cleanup not confirmed' }
 $guarded=@(Get-Guarded $s)
 if($guarded.Count){Set-PacketFilters 0 $guarded @()}
 if ($sessionExists -and (Test-Path -LiteralPath $statePath)) { Remove-Item -LiteralPath $statePath }
 if (Test-Path -LiteralPath $journalPath) { Remove-Item -LiteralPath $journalPath }
}
function Add-Route([string]$IP) {
 Assert-IP $IP; $prefix=$IP+'/32'
 if ($script:state.Routes -contains $prefix) { return }
 if ($script:state.Routes.Count -ge (2*$routeLimit)) { throw 'Route journal bound' }
 $existing=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $script:state.Index -and $_.DestinationPrefix -eq $prefix })
 if ($existing.Count) { throw 'Conflicting pre-existing work route' }
 $script:state.Routes=@($script:state.Routes)+@($prefix); Save-State
 New-NetRoute -InterfaceIndex $script:state.Index -DestinationPrefix $prefix -NextHop $script:state.Address -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}
function Get-OwnedRoute([string]$Prefix) {
 Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $script:state.Index -and $_.DestinationPrefix -eq $Prefix -and $_.NextHop -eq $script:state.Address -and $_.RouteMetric -eq 1 }
}
function Remove-OwnedRoute([string]$Prefix) {
 foreach($route in @(Get-OwnedRoute $Prefix)) { $route | Remove-NetRoute -Confirm:$false }
 $script:state.Routes=@($script:state.Routes|Where-Object {$_ -ne $Prefix});Save-State
}
function Get-OwnedDnsRule {
 $rules=@(Get-DnsClientNrptRule | Where-Object Comment -eq $tag)
 if ($rules.Count -gt 1) { throw 'Ambiguous session DNS rule' }
 if ($rules.Count) { return $rules[0] }
}
function Set-WorkDns([string[]]$Names) {
 $rule=Get-OwnedDnsRule
 if ($null -eq $rule) {
  if ($Names.Count) { Add-DnsClientNrptRule -Namespace $Names -NameServers $script:state.Dns -Comment $tag -DisplayName 'Forti Split Work' | Out-Null }
 } elseif (!$Names.Count) {
  Remove-DnsClientNrptRule -Name $rule.Name -Force
  } elseif ($rule.Namespace.Count -ne $Names.Count -or @($rule.Namespace | Where-Object { $Names -notcontains $_ }).Count -or
            @($rule.NameServers).Count -ne $script:state.Dns.Count -or @($rule.NameServers | Where-Object { $script:state.Dns -notcontains $_ }).Count) {
   Set-DnsClientNrptRule -Name $rule.Name -Namespace $Names -NameServers $script:state.Dns
 }
}
# Exit 2 preserves the previous settings. Exit 3 defers work to a newer tunnel.
$exitCode=1
try {
 if ($Mode -eq 'Hook' -and !(Test-Path -LiteralPath $hookLeasePath -PathType Leaf)) { return }
 if ($Mode -eq 'Hook' -and $env:reason -eq 'attempt-reconnect') {
  New-Item -ItemType File -Path $reconnectingPath -Force | Out-Null
  return
 }
 if ($Mode -eq 'Hook' -and $env:reason -notin @('connect','reconnect')) { return }
 if ($Mode -eq 'Hook' -and $env:reason -eq 'reconnect') {
  New-Item -ItemType File -Path $reconnectingPath -Force | Out-Null
 }
 try { $locked=$mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $locked=$true }
 if (-not $locked) { throw 'Network operation still running' }
 if ($Mode -eq 'Hook' -and !(Test-Path -LiteralPath $hookLeasePath -PathType Leaf)) { return }
 if ($Mode -eq 'Cleanup') { Cleanup; return }
 if ($Mode -ne 'Hook') {
  $script:state=Read-State
  if ($Generation -and ((Test-Path -LiteralPath $reconnectingPath) -or $null -eq $script:state -or $script:state.Generation -ne $Generation)) { exit 3 }
  if ($null -eq $script:state) { throw 'Tunnel settings unavailable' }
  if ($Mode -in @('Apply','Continue','Retry') -and $script:state.Stage -ne 'ready') { exit 3 }
 }
 $configPath=$activeConfigPath
 if ($Mode -eq 'Apply') { $configPath=Join-Path $Session 'candidate-config.json' }
 if ((Get-Item -LiteralPath $configPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Config link refused' }
 $config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
 $optionalHosts=@(); if ($config.PSObject.Properties['OptionalHosts']) { $optionalHosts=@($config.OptionalHosts) }
 $domains=@();if($config.PSObject.Properties['DnsDomains']){$domains=@($config.DnsDomains)}
 if($domains.Count -gt 8){throw 'DNS domain count bound'}
 foreach($domain in $domains){Assert-Host $domain;$parsed=$null;if([Net.IPAddress]::TryParse($domain,[ref]$parsed)){throw 'DNS domain must not be an IP'}}
 $domainNamespaces=@($domains|ForEach-Object {'.'+$_})
 if (@($config.Hosts).Count + $optionalHosts.Count -gt 40) { throw 'Host count bound' }
 foreach ($name in @($config.Hosts)+$optionalHosts) { Assert-Host $name }
 $workNamespaces=@(@($domainNamespaces)+@($config.Hosts|Where-Object {$_ -match '[a-zA-Z]'})|Select-Object -Unique)
 if ($Mode -eq 'Hook') {
  if ($env:TUNIDX -notmatch '^\d+$') { throw 'No tunnel adapter index' }
  $index=[int]$env:TUNIDX; $address=$env:INTERNAL_IP4_ADDRESS; Assert-IP $address
  $adapter=Get-NetAdapter -InterfaceIndex $index
  if ($adapter.Name -ne 'FortiSplitWork') { throw 'Unexpected tunnel adapter' }
  $dns=@($env:INTERNAL_IP4_DNS -split '\s+' | Where-Object { $_ })
  if ($dns.Count -lt 1 -or $dns.Count -gt 4) { throw 'Missing or excessive VPN DNS' }
  foreach ($ip in $dns) { Assert-IP $ip }
  $literals=@($config.Hosts|Where-Object {Test-IPv4 $_})
  $bootstrap=@($dns+$literals|Sort-Object -Unique)
  $gateway=$env:VPNGATEWAY
  if($gateway -and $bootstrap -contains $gateway){throw 'Work addresses conflict with the VPN gateway'}
  $script:state=Read-State
  $guarded=@();$retainedNames=@();$previousResolved=@()
  if ($null -ne $script:state) {
   $guarded=@(@(Get-Guarded $script:state)+$bootstrap|Sort-Object -Unique)
   Set-Guard $guarded $index
   $oldRule=Get-OwnedDnsRule
   if($null -ne $oldRule){$retainedNames=@($oldRule.Namespace)}
   $previousResolved=@($script:state.Resolved)
   Clear-Tunnel $script:state
  }
  $script:state=[pscustomobject]@{ Tag=$tag; Index=$index; Guid=[string]$adapter.InterfaceGuid; Address=$address; AddedAddress=$false; Routes=@(); Dns=$dns; Stage='configuring'; Generation=[guid]::NewGuid().ToString('N'); OriginalMtu=(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4).NlMtu; Resolved=$previousResolved; Guarded=$guarded; GuardIndex=$index; Gateway=$gateway }
  Save-State
  if(!$guarded.Count){Set-Guard $bootstrap $index}
  if (-not @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $index -and $_.IPAddress -eq $address }).Count) {
   $script:state.AddedAddress=$true; Save-State
   New-NetIPAddress -InterfaceIndex $index -IPAddress $address -PrefixLength 32 -PolicyStore ActiveStore | Out-Null
  }
  if ($env:INTERNAL_IP4_MTU -match '^\d+$') { $mtu=[int]$env:INTERNAL_IP4_MTU; if ($mtu -ge 576 -and $mtu -le 9000) { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -NlMtuBytes $mtu -PolicyStore ActiveStore } }
  foreach ($ip in $dns) { Add-Route $ip }
  # Bootstrap IPs and private-domain DNS must be ready before the first lookup.
  # OpenConnect's synchronous hook must not wait for a query through this tunnel.
  foreach($name in $literals){Add-Route $name}
  Set-WorkDns @($retainedNames+$workNamespaces|Select-Object -Unique)
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  $script:state.Stage='base_ready'; Save-State
  foreach ($path in @($hookErrorPath,$reconnectingPath)) {
   if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
  }
  return
 }
 $adapter=Get-NetAdapter -InterfaceIndex $script:state.Index
 if($adapter.Name -ne 'FortiSplitWork' -or [string]$adapter.InterfaceGuid -ne $script:state.Guid){throw 'Tunnel adapter changed'}
 # This runs AFTER the synchronous OpenConnect hook, so tunnel receive stays live.
 $previousState=$script:state | ConvertTo-Json -Depth 8 | ConvertFrom-Json
 $previous=@($script:state.Resolved);$previousUnresolved=@();if($script:state.PSObject.Properties['Unresolved']){$previousUnresolved=@($script:state.Unresolved)}
 $resolved=@(); $unresolved=@(); $deferred=@(); $dnsFailures=@()
 $hosts=@(@($config.Hosts)+$optionalHosts|Select-Object -Unique)
 $previousDeferred=@()
 if ($Mode -eq 'Continue' -and $script:state.PSObject.Properties['Deferred']) {
  $previousDeferred=@($script:state.Deferred)
  if ($script:state.PSObject.Properties['DnsFailures']) { $dnsFailures=@($script:state.DnsFailures) }
 }
 if ($Mode -eq 'Retry' -and $script:state.PSObject.Properties['RetryDeferred']) {
  $priority=@($script:state.RetryDeferred | Where-Object { $hosts -contains $_ })
  $hosts=@($priority + @($hosts | Where-Object { $priority -notcontains $_ }))
 }
 # A continuation spends its entire budget on names still waiting for a first query.
 $lookupTimer=[Diagnostics.Stopwatch]::new()
 foreach ($name in $hosts) {
  $literal=$null; $addresses=@(); $queried=$false
  $saved=@($previous|Where-Object Host -eq $name)
  if ($Mode -eq 'Continue' -and $previousDeferred -notcontains $name) {
   if ($saved.Count) { $resolved+=@($saved[0]) }
   if ($previousUnresolved -contains $name) { $unresolved+=@($name) }
   continue
  }
  if($Mode -eq 'Retry' -and $saved.Count -and $previousUnresolved -notcontains $name){$resolved+=@($saved[0]);continue}
  if ([Net.IPAddress]::TryParse($name,[ref]$literal)) { Assert-IP $name; $addresses=@($name) }
  else {
   foreach ($server in $script:state.Dns) {
    if($lookupTimer.Elapsed.TotalSeconds -ge 15){break}
    foreach ($tcp in @($false,$true)) {
     if (Test-Path -LiteralPath $reconnectingPath) { exit 3 }
     if($lookupTimer.Elapsed.TotalSeconds -ge 15){break}
     $queried=$true
     $lookupTimer.Start()
     try {
      $query=@{Name=$name;Server=$server;Type='A';DnsOnly=$true;QuickTimeout=$true;ErrorAction='Stop'}
      if ($tcp) { $query.TcpOnly=$true }
      $addresses=@(Resolve-DnsName @query |
       Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.Type -eq 1 -and (Test-IPv4 $_.IPAddress) } |
       Select-Object -ExpandProperty IPAddress -Unique)
      if ($addresses.Count) { break }
     } catch { $dnsFailures+=@([pscustomobject]@{Host=$name;Server=$server;Transport=$(if($tcp){'TCP'}else{'UDP'});ErrorType=$_.Exception.GetType().Name}) }
    }
    if ($addresses.Count) { break }
   }
   if (!$queried) { $deferred+=@($name) }
  }
  if (-not $addresses.Count -or $addresses.Count -gt 16) {
   $unresolved+=@($name)
   # Retain a working route during a transient DNS failure. Explicitly removed
   # names are not in this loop and therefore lose their routes below.
   if($saved.Count){$resolved+=@($saved[0])}
   continue
  }
  $resolved+=@([pscustomobject]@{Host=$name;Addresses=$addresses})
 }
 if (Test-Path -LiteralPath $reconnectingPath) { exit 3 }
 # Add replacement routes first, then retire only obsolete routes owned by this
 # session. Shared IPs and VPN DNS routes remain until their last user is removed.
 $desiredIps=@(@($script:state.Dns)+@($resolved|ForEach-Object Addresses)|Sort-Object -Unique)
 if($script:state.PSObject.Properties['Gateway'] -and $script:state.Gateway -and $desiredIps -contains $script:state.Gateway){
  if($Mode -eq 'Apply'){$exitCode=2}
  throw 'Work addresses conflict with the VPN gateway'
 }
 $desired=@($desiredIps|ForEach-Object {Assert-IP $_;$_+'/32'})
 if ($desired.Count -gt $routeLimit) {
  $exitCode=2
  throw "Route count exceeds $routeLimit"
 }
 # Mandatory work names get exact DNS rules even if their first lookup fails.
 $names=@(@($workNamespaces)+@($resolved | ForEach-Object Host | Where-Object { $_ -match '[a-zA-Z]' }) | Select-Object -Unique)
 $previousRule=Get-OwnedDnsRule
 $previousNames=@()
 if ($null -ne $previousRule) { $previousNames=@($previousRule.Namespace) }
 $add=@($desired | Where-Object { $previousState.Routes -notcontains $_ })
 $remove=@($previousState.Routes | Where-Object { $desired -notcontains $_ })
 try {
  $script:state.Stage='resolving'; Save-State
  Set-Guard @(@(Get-Guarded $previousState)+$desiredIps|Sort-Object -Unique) $script:state.Index
  foreach ($prefix in $add) { Add-Route $prefix.Substring(0,$prefix.Length-3) }
  Set-WorkDns $names
  foreach ($prefix in $remove) { Remove-OwnedRoute $prefix }
  $script:state | Add-Member -NotePropertyName Unresolved -NotePropertyValue $unresolved -Force
  if ($Mode -eq 'Retry') {
   $script:state | Add-Member -NotePropertyName RetryDeferred -NotePropertyValue $deferred -Force
  } else {
   $script:state | Add-Member -NotePropertyName Deferred -NotePropertyValue $deferred -Force
   $script:state | Add-Member -NotePropertyName RetryDeferred -NotePropertyValue @() -Force
  }
  $script:state | Add-Member -NotePropertyName DnsFailures -NotePropertyValue $dnsFailures -Force
  $script:state.Resolved=$resolved; $script:state.Stage='ready'; Save-State
  if ($Mode -eq 'Apply') { [IO.File]::Replace($configPath,$activeConfigPath,[NullString]::Value) }
 } catch {
  $failure=$_
  # Restore routes before reinstating their DNS policy, then remove candidate routes.
  foreach ($prefix in $remove) {
   if (!@(Get-OwnedRoute $prefix).Count) {
    $script:state.Routes=@($script:state.Routes | Where-Object { $_ -ne $prefix })
    Add-Route $prefix.Substring(0,$prefix.Length-3)
   }
  }
  Set-WorkDns $previousNames
  foreach ($prefix in @($script:state.Routes)) {
   if ($previousState.Routes -notcontains $prefix) { Remove-OwnedRoute $prefix }
  }
  Set-Guard @(Get-Guarded $previousState) $script:state.Index
  $script:state=$previousState; Save-State
  Clear-DnsClientCache -ErrorAction SilentlyContinue
  $exitCode=2
  throw $failure
 }
 # Retain prior answers across reconnects. An explicit changeset releases addresses it superseded.
 if ($Mode -eq 'Apply') { Set-Guard $desiredIps $script:state.Index }
 Clear-DnsClientCache -ErrorAction SilentlyContinue
} catch {
 # No auth environment or secrets are written here.
 $message=$_.Exception.Message
 $errorPath=if ($Mode -eq 'Hook') { $hookErrorPath } else { Join-Path $Session 'network-error.txt' }
 if ($sessionExists) { [IO.File]::WriteAllText($errorPath,$message) }
 Write-Error $message -ErrorAction Continue
 exit $exitCode
} finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
