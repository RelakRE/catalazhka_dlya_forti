# Windows verification

From this directory, run `./test-work.ps1` with Python 3, .NET SDK 10 and
Windows PowerShell 5.1 available. This is also the pull request workflow entry
point. It audits the public export, runs Python and .NET checks, simulates
network setup and recovery, checks the Windows network cmdlet schema, publishes
the app and runs its native offline self-test. Runtime preparation downloads
the pinned upstream components and verifies their SHA-256. Find the native
report in `build/work-tests/`. Pass `-SourceOnly` to run the checks through the
network schema without publishing the app or preparing its runtime.

## Windows 11 acceptance with a test VPN

Use a Windows 11 x64 test machine, a test account with MFA and authorized test
RDP and TrueConf endpoints. Record the tested commit, Windows build, app and VPN
runtime versions, and pass/fail for each step. Keep profiles, addresses and
unredacted captures in the test environment.

1. Start from a fresh copy of the release ZIP. Import a test profile, connect,
   approve UAC and wait for the protected runtime to be prepared. Complete MFA.
   On the next connection, check the worker runs from Program Files. Confirm
   the desktop can read its session output and cannot modify it. Cancel one MFA
   attempt and retry.
2. Open a work RDP session, join a TrueConf call with audio/video, and load a
   public site. Confirm the work routes use the VPN and the default internet
   route stays on the physical interface. Record route and DNS-rule ownership.
3. On the Work tab, check a known VPN IPv4 with an open TCP port, a refused
   port and a filtered port. Confirm results distinguish them. Check an IPv4
   outside the VPN and confirm the diagnostic sends no ICMP or TCP to it.
   Close a running diagnostic and repeat with a tunnel disconnect during it.
4. Generate bidirectional traffic to a configured work IP with Windows Firewall
   enabled. Verify the address appears, its receive and send totals and rates
   reflect the traffic, and it expires after traffic stops. Change a work address
   during the session, then repeat with a tunnel loss during application. Check
   the UI reports success only after applying the new configuration. Verify the
   profile still contains the last successfully applied list after a failed change.
5. Exercise normal disconnect, forced GUI exit, unexpected VPN loss, sleep/wake
   and a network change. Check that VPN readiness returns after route and DNS
   setup completes. If recovery is required, complete it and reconnect. Compare the
   default route and DNS rules with the first snapshot. Session-owned entries
   should be removed and unrelated entries should remain. Use a dual-stack
   test name and confirm the observed IPv6 address stays blocked during reconnect.
   After an unexpected loss, repeat recovery from a second administrator account.
6. Update a disposable copy from an older supported build and confirm the
   saved profile survives. In a controlled update-failure test, confirm the
   previous build opens and the same profile is retained.
