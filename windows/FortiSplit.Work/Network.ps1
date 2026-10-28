param([ValidateSet('Hook','Resolve','Cleanup','Preflight')][string]$Mode='Hook',[Parameter(Mandatory=$true)][string]$Session)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 3
$Session=[IO.Path]::GetFullPath($Session)
$root=Join-Path $env:LOCALAPPDATA 'Forti Split Work\sessions'
if ([IO.Path]::GetDirectoryName($Session) -ne $root -or [IO.Path]::GetFileName($Session) -notmatch '^[a-f0-9]{32}$') { throw 'Invalid session path' }
for ($part=Get-Item -LiteralPath $Session; $null -ne $part; $part=$part.Parent) { if ($part.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path refused' } }
$statePath=Join-Path $Session 'network.json'
$tag='FortiSplitWork-'+[IO.Path]::GetFileName($Session)
$mutex=New-Object Threading.Mutex($false,'Global\FortiSplitWork-Network')
$locked=$false
function Save-State {
 $tmp=$statePath+'.tmp'
 foreach ($p in @($statePath,$tmp)) { if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'State link refused' } }
 $script:state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
 Move-Item -LiteralPath $tmp -Destination $statePath -Force
}
function Assert-IP([string]$IP) {
 $parsed=$null
 if (-not [Net.IPAddress]::TryParse($IP,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -ne $IP) { throw 'Invalid IPv4' }
 $b=$parsed.GetAddressBytes(); if ($b[0] -eq 0 -or $b[0] -eq 127 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)) { throw 'Invalid IPv4 scope' }
}
function Assert-Host([string]$HostName) {
 if ($HostName.Length -gt 253 -or $HostName -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { throw 'Invalid work host' }
 foreach ($label in $HostName.Split('.')) { if ($label.Length -gt 63 -or $label.StartsWith('-') -or $label.EndsWith('-')) { throw 'Invalid label' } }
}
function Read-State {
 if (-not (Test-Path -LiteralPath $statePath)) { return $null }
 if ((Get-Item -LiteralPath $statePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State link refused' }
 $s=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
 if ($s.Tag -ne $tag -or $s.Index -le 0 -or $s.Routes.Count -gt 256) { throw 'Invalid recovery state' }
 Assert-IP $s.Address
 foreach ($prefix in $s.Routes) { if (-not $prefix.EndsWith('/32')) { throw 'Non-host recovery route' }; Assert-IP $prefix.Substring(0,$prefix.Length-3) }
 return $s
}
function Cleanup {
 $s=Read-State
 foreach ($rule in @(Get-DnsClientNrptRule | Where-Object Comment -eq $tag)) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
 if ($null -eq $s) { return }
 $adapter=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.ifIndex -eq $s.Index -and [string]$_.InterfaceGuid -eq $s.Guid -and $_.Name -eq 'FortiSplitWork' })
 if ($adapter.Count -eq 1) {
  foreach ($prefix in $s.Routes) {
   foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $s.Index -and $_.DestinationPrefix -eq $prefix -and $_.NextHop -eq $s.Address -and $_.RouteMetric -eq 1 })) { $route | Remove-NetRoute -Confirm:$false }
  }
  if ($s.AddedAddress) { foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $s.Index -and $_.IPAddress -eq $s.Address })) { $ip | Remove-NetIPAddress -Confirm:$false } }
  if ($s.OriginalMtu -gt 0) { Set-NetIPInterface -InterfaceIndex $s.Index -AddressFamily IPv4 -NlMtuBytes $s.OriginalMtu -PolicyStore ActiveStore }
  if (@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $s.Index -and $s.Routes -contains $_.DestinationPrefix -and $_.NextHop -eq $s.Address -and $_.RouteMetric -eq 1 }).Count) { throw 'Route cleanup not confirmed' }
  if ($s.AddedAddress -and @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $s.Index -and $_.IPAddress -eq $s.Address }).Count) { throw 'IP cleanup not confirmed' }
 }
 if (@(Get-DnsClientNrptRule | Where-Object Comment -eq $tag).Count) { throw 'DNS cleanup not confirmed' }
 Remove-Item -LiteralPath $statePath
}
function Add-Route([string]$IP) {
 Assert-IP $IP; $prefix=$IP+'/32'
 if ($script:state.Routes -contains $prefix) { return }
 if ($script:state.Routes.Count -ge 256) { throw 'Route count bound' }
 $existing=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -eq $script:state.Index -and $_.DestinationPrefix -eq $prefix })
 if ($existing.Count) { throw 'Conflicting pre-existing work route' }
 $script:state.Routes=@($script:state.Routes)+@($prefix); Save-State
 New-NetRoute -InterfaceIndex $script:state.Index -DestinationPrefix $prefix -NextHop $script:state.Address -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}
try {
 try { $locked=$mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $locked=$true }
 if (-not $locked) { throw 'Network operation still running' }
 if ($Mode -eq 'Preflight') {
  if (@(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Fortinet' }).Count) { throw 'Отключите FortiClient: новый клиент подключается вместо него.' }
  if (@(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -eq 'FortiSplitWork' }).Count) { throw 'Адаптер нового клиента уже активен. Сначала восстановите предыдущий сеанс.' }
  Write-Output 'ok'; return
 }
 if ($Mode -eq 'Cleanup' -or ($Mode -eq 'Hook' -and $env:reason -eq 'disconnect')) { Cleanup; return }
 if ($Mode -eq 'Hook' -and $env:reason -notin @('connect','reconnect')) { return }
 $configPath=Join-Path $Session 'config.json'
 if ((Get-Item -LiteralPath $configPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Config link refused' }
 $config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
 $optionalHosts=@(); if ($config.PSObject.Properties['OptionalHosts']) { $optionalHosts=@($config.OptionalHosts) }
 if (@($config.Hosts).Count + $optionalHosts.Count -gt 40) { throw 'Host count bound' }
 foreach ($name in @($config.Hosts)+$optionalHosts) { Assert-Host $name }
 if ($Mode -eq 'Hook') {
  if ($env:TUNIDX -notmatch '^\d+$') { throw 'No tunnel adapter index' }
  $index=[int]$env:TUNIDX; $address=$env:INTERNAL_IP4_ADDRESS; Assert-IP $address
  $adapter=Get-NetAdapter -InterfaceIndex $index
  if ($adapter.Name -ne 'FortiSplitWork') { throw 'Unexpected tunnel adapter' }
  $dns=@($env:INTERNAL_IP4_DNS -split '\s+' | Where-Object { $_ })
  if ($dns.Count -lt 1 -or $dns.Count -gt 4) { throw 'Missing or excessive VPN DNS' }
  foreach ($ip in $dns) { Assert-IP $ip }
  Cleanup
  $script:state=[pscustomobject]@{ Tag=$tag; Index=$index; Guid=[string]$adapter.InterfaceGuid; Address=$address; AddedAddress=$false; Routes=@(); Dns=$dns; Stage='configuring'; Generation=[guid]::NewGuid().ToString('N'); OriginalMtu=(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4).NlMtu; Resolved=@() }
  Save-State
  if (-not @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $index -and $_.IPAddress -eq $address }).Count) {
   $script:state.AddedAddress=$true; Save-State
   New-NetIPAddress -InterfaceIndex $index -IPAddress $address -PrefixLength 32 -PolicyStore ActiveStore | Out-Null
  }
  if ($env:INTERNAL_IP4_MTU -match '^\d+$') { $mtu=[int]$env:INTERNAL_IP4_MTU; if ($mtu -ge 576 -and $mtu -le 9000) { Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -NlMtuBytes $mtu -PolicyStore ActiveStore } }
  foreach ($ip in $dns) { Add-Route $ip }
  $script:state.Stage='base_ready'; Save-State
  return
 }
 $script:state=Read-State
 if ($null -eq $script:state) { throw 'Tunnel settings unavailable' }
 # This runs AFTER the synchronous OpenConnect hook, so tunnel receive stays live.
 $script:state.Stage='resolving'; Save-State
 $resolved=@()
 foreach ($name in @($config.Hosts)+$optionalHosts) {
  $literal=$null; $addresses=@()
  if ([Net.IPAddress]::TryParse($name,[ref]$literal)) { Assert-IP $name; $addresses=@($name) }
  else {
   foreach ($server in $script:state.Dns) {
    try { $addresses=@(Resolve-DnsName -Name $name -Server $server -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress -Unique); if ($addresses.Count) { break } } catch { }
   }
  }
  if (-not $addresses.Count) {
   if ($optionalHosts -contains $name -and @($config.Hosts) -notcontains $name) { continue }
   throw ('Рабочее имя не разрешено: '+$name)
  }
  if ($addresses.Count -gt 16) { throw ('Слишком много адресов рабочего имени: '+$name) }
  foreach ($ip in $addresses) { Add-Route $ip }
  $resolved+=@([pscustomobject]@{Host=$name;Addresses=$addresses})
 }
 # Exact work names only. Never replace home DNS or the internet default route.
 $names=@($resolved | ForEach-Object Host | Where-Object { $_ -match '[a-zA-Z]' } | Select-Object -Unique)
 foreach ($rule in @(Get-DnsClientNrptRule)+@(Get-DnsClientNrptPolicy -Effective)) {
  if ($rule.PSObject.Properties['Comment'] -and $rule.Comment -eq $tag) { continue }
  foreach ($ns in @($rule.Namespace)) {
   foreach ($name in $names) { if ($ns -eq '.' -or $ns -eq $name -or ($ns.StartsWith('.') -and $name.EndsWith($ns,[StringComparison]::OrdinalIgnoreCase))) { throw 'Existing DNS policy overlaps work names' } }
  }
 }
 foreach ($rule in @(Get-DnsClientNrptRule | Where-Object Comment -eq $tag)) { Remove-DnsClientNrptRule -Name $rule.Name -Force }
 if ($names.Count) { Add-DnsClientNrptRule -Namespace $names -NameServers $script:state.Dns -Comment $tag -DisplayName 'Forti Split Work' | Out-Null }
 $script:state.Resolved=$resolved; $script:state.Stage='ready'; Save-State
} catch {
 # No auth environment or secrets are written here.
 $message=$_.Exception.Message
 [IO.File]::WriteAllText((Join-Path $Session 'network-error.txt'),$message)
 Write-Error $message -ErrorAction Continue
 exit 1
} finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
