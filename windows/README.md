# Forti Split for Windows

Desktop client for Fortinet SSL VPN using OpenConnect. Work services use host routes
through the VPN; the normal internet connection keeps its default route.

The UI provides connect/disconnect, RDP and TrueConf launch, tray status, profile
import/export and recovery. Login, password and second-factor forms appear in the app.
The Work tab shows VPN totals and transfer rates in both directions. For each
configured work IP active in the last five seconds, it also shows observed IPv4
bytes for the session and the latest byte rate, separately for receive and send.
Names sharing an IP use a single row. Click a work address to open its diagnostics.
Per-address volumes include the IP headers. The overall totals cover the full VPN
interface, including traffic to addresses that are absent from the table.
Per-address statistics use the Windows Packet Monitor real-time API and show as
unavailable when that API cannot capture on the VPN adapter.
Each address activity period shows the local date and time of its first and last
observed packets and the elapsed time between them. More than five seconds of
inactivity, tunnel reconnection, or disconnect ends the period. The Work tab keeps
the five most recent completed periods while the app remains open.
Passwords are saved only when requested, in Windows Credential Manager. OTP values
and session cookies are never saved in profiles or logs.

## Download and first launch

Download the Windows preview tagged `windows-v…` from [Releases](https://github.com/RelakRE/catalazhka_dlya_forti/releases).
Extract the complete archive and run `Forti Split.exe`. .NET is included.
On the first connection, UAC authorizes installation of the network worker.
The worker downloads OpenConnect 9.21 and Wintun 0.14.1 into a protected folder in
Program Files and verifies the upstream archives against pinned SHA-256 values.
Internet access is required for that preparation. Later connections use the
installed worker and verify the cached VPN runtime against its protected manifest.
See [release notes](RELEASE-NOTES.md).

## Update notifications

The app checks the public GitHub release list once at startup. It looks for newer
Windows releases, including previews, with the expected Windows x64 ZIP. In Settings,
**Открыть выпуск** opens the project release page. An unavailable network does not
block VPN use. The check sends no VPN profile, credentials or authentication codes.

When a verifiable update is available, **Обновить** downloads and checks the release after
the user disconnects the VPN. The app verifies the archive's publisher signature
against the embedded public key for releases that use that format. GitHub releases
use a Sigstore attestation from the project's Windows Release workflow on `main`.
The app checks the archive size and SHA-256 and installs it into LocalAppData. Settings are retained, and
the new worker reuses the protected VPN runtime if its versions match.
The app retains the signed archive and checks the installed executable against it
before handing off a launch or elevating an updated build for the first time.
For a 1.2.7 installer that discards the ZIP, releases starting with 1.2.14
include a separate signature or workflow attestation for the executable under
`licenses/`, a directory that the old ZIP extractor preserves. The updated app
verifies its executable before signalling readiness. Future updates retain the
executable hash in the launcher link so the original shortcut keeps working.
The app switches to the new version only
after preparation and restarts it; the previous installation remains available if
the switch fails. **Открыть выпуск** remains available for manual installation.
Automatic installation requires the restart marker and a `.zip.sigstore.json`
attestation, or a `.zip.sig` and the corresponding embedded publisher key.
Verification of a build attestation may need network access to refresh Sigstore
trust data. **Открыть выпуск** remains available for releases without proof.

From 1.2.7 with a prepared VPN runtime, choose **Обновить** when 1.2.14 or later is offered.
From the published 1.2.12 preview, which requires a publisher signature
to enable that button, extract the new release into a separate folder and launch
`Forti Split.exe` from there. Update any existing shortcut to point to that file.
The app reads the same Windows VPN profile and saved credentials. Later attested
releases can be installed with **Обновить**.

## Build from source

Windows x64, .NET SDK 10 and Windows PowerShell 5.1 are required.

    dotnet restore FortiSplit.Work/FortiSplit.Work.csproj
    dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release --no-restore -o build/FortiSplit
    ./test-work.ps1

The verification command also requires Python 3. See [TESTING.md](TESTING.md)
for test reports, source-only checks and Windows 11 VPN acceptance.

Runtime binaries are excluded from this source tree and the release archive.
`--prepare-runtime` prepares a local copy for offline validation.
`prepare-work.ps1 -ClientDirectory <local-runtime-directory>` can also
copy an existing compatible runtime for testing. VPN connections use the
worker's protected installation. The native API binding supports the
OpenConnect 9.12 public ABI and is checked offline with 9.21 for this release.
Run `./build-release.ps1` in a clean checkout to create and validate release assets.
To sign update archives, run the same script in PowerShell 7 with
`-UpdateSigningThumbprint` set to the thumbprint of the publisher's 3072–4096-bit
RSA certificate in `Cert:\CurrentUser\My`. The build embeds its public key and
emits an RSA-PSS/SHA-256 `.zip.sig` asset. Keep the signing key outside the repository.

### Publish a Windows release

Update the version in `FortiSplit.Work.csproj` and add the corresponding section
to `RELEASE-NOTES.md`. Merge those changes into `main`, then run the
**Windows Release** workflow on `main`. The workflow runs offline validation,
generates a GitHub Actions attestation for the ZIP, and verifies it with the
built app before publishing both files. Developers with permission to run the
workflow can publish without keeping a personal signing certificate or setting
repository secrets. Windows Authenticode signing is independent.

## Profiles

`profile.example.json` contains documentation-only placeholders. Set your real VPN
server, local RDP file and optional TrueConf settings in the app or import a private
JSON profile. Existing profiles under `%LOCALAPPDATA%\Forti Split Work` are reused.
Private profile exports end in `.local.json` and must stay outside Git.

`ExtraHosts` can contain DNS names, IPv4 addresses, or a mixture. Open Settings →
**Рабочие адреса** and add each entry in **Добавить рабочий адрес**.
Full HTTP/HTTPS links are accepted and stored as hostnames. JSON profiles retain
the existing hostname/IPv4 format. Optional private
DNS suffixes in `DnsDomains` have no leading dot; each explicitly added hostname
gets its own exact DNS rule even without a suffix. Redirects to another hostname
require adding that hostname too. Work routes use IPv4. The VPN gateway
hostname can resolve to IPv4 or IPv6. The worker checks A and AAAA answers for
work names on the VPN DNS servers. It blocks the observed IPv6 destinations
on all interfaces, as the tunnel only carries IPv4.
An address that matches the VPN gateway is skipped so the VPN connection keeps
its physical route. The app reports skipped work addresses and sets up the
remaining routes.

VPN DNS routes, optional literal IP routes and work-name/domain DNS rules are
installed before any tunnel DNS query. DNS lookup runs after the synchronous
OpenConnect hook and uses the VPN's DNS servers for every attempt. A lookup pass
stops starting queries 15 seconds after its first query. An in-flight QuickTimeout
query may finish later. The next pass processes names that have yet to receive
their first query. Once those queries have run, unresolved names get up to three
additional attempts after 3, 10 and 30 seconds. An unresolved name does not
disconnect the VPN and its count appears in the connected status.

While connected, edit the work addresses and DNS domains, then use the fixed
**Применить рабочие адреса** button at the bottom of Settings. This resolves their
current IPs without reconnecting or entering 2FA again and saves the profile after
the network update succeeds. The elevated worker validates a bounded request from
the private user folder and applies it in a protected session directory. The
request is limited to work addresses and DNS domains.
Replacement routes are added before obsolete session-owned routes are removed.
An IP shared by another work name or VPN DNS is retained. A temporary DNS failure
keeps that name's previous routes; deleting the name explicitly removes routes
no longer needed elsewhere. The app checks the 256-route limit before changing the
table. If an update fails, it attempts to restore the previous routes and DNS rules.
Disconnect/recovery removes all session-owned changes.
Windows Filtering Platform blocks the session's known work IPv4 and VPN DNS
destinations on other interfaces, including while reconnecting. The app keeps the
previous DNS rules during the transition. Earlier work addresses stay protected
until the next explicit change of work addresses, disconnect, or recovery.
There is no continuous DNS polling or TTL-based refresh; applying addresses or
reconnecting performs a fresh lookup. Use actual internal values in private
profiles; public examples remain blank.

Any selected local RDP file is passed unchanged to mstsc, including short computer
names and system gateway profiles. Recognizable endpoints are best-effort route
hints only. DNS failure for a target, gateway or other work endpoint does not stop
the authenticated VPN tunnel; actual RDP errors are handled by the Windows client.
While connected, open **Проверить адрес** on the Work tab or select an
entry in Settings and open **Проверить адрес**. By default **Проверить** looks up
the Windows route and measures ICMP round-trip time over VPN. To include a TCP
check, select RD Gateway (443), direct RDP (3389), HTTP/HTTPS, or a custom port.
The route, ping, and TCP results appear separately.
Work routes and DNS are configured on connection, actual OpenConnect reconnect,
bounded retries of unresolved names, and explicit application of work addresses.
There are no periodic network diagnostics or internet probes.
Disconnect/Exit removes the session's settings. The worker also attempts cleanup
if the UI exits unexpectedly or network setup fails during reconnection. When the
app reports that recovery is required, press Restore Network and approve UAC.
The elevated worker can restore the app's machine-wide network changes from
protected journals, including after the original Windows account is gone. It
stops only recorded VPN processes and removes the app's own settings.
Existing profiles and private credentials are reused.
New sessions record the adapter GUID in a protected journal, so recovery follows
a renamed tunnel. Recovery can retire the user-side marker for a legacy VPN
process that has already exited. A still-running legacy process or a network
journal with no protected original or cleanup record needs administrator assistance.

For a fresh installation, set the server under Settings → **VPN**, then select the
RDP file and configure TrueConf as needed under **Приложения**. Profiles, network
recovery, logs, and updates are under **Обслуживание**. Enter the password and OTP
when connecting.
Disconnect FortiClient before using this app. Connecting and restoring the network
require a Windows account that can approve UAC under its own name. The network
worker runs elevated, while the UI and launched work apps retain ordinary user rights.

Every settings field and option has a short description and a clickable **?**.
The help window explains the input format, where to obtain the value, and when it
can be left empty. Examples are always fictional documentation-only values, clearly
marked as examples. Help never reads current field values or profile data.
Help remains available while settings
are locked by an active VPN session. It does not change settings or send examples
anywhere; real addresses and usernames are never embedded in public help sources.

## Verification limits

Offline tests cover configuration, native ABI initialization, Credential Manager,
private IPC and mocked network setup/recovery. They do not prove compatibility with
every gateway or successful RDP login/video calls. A real login requires user credentials.
During authentication, the network wait after submitting a recognized one-time
code is 30 seconds. Other network waits have a 90-second limit. Time spent entering
credentials or a code is excluded. Explicit code rejection and expiration have
distinct messages when OpenConnect exposes them. The timeout message shows the
latest HTTP status from the current step when available. Known HTTPS connection,
HTTP parsing and response read errors are shown when reported before the deadline
and no new HTTP response supersedes them. A timeout permanently
ends that authentication attempt: subsequent native callbacks cannot show another
form or restart the deadline. A failed HTTP response read also stops repeated form
callbacks instead of asking for another MFA response. A private
`auth-stage.json` records only the latest fixed phase name, step number and UTC
timestamp. `auth-trace.json` retains up to 160 fixed phase/form-category events and
numeric HTTP status codes, with timestamps; neither file retains form contents,
credentials, server response bodies, headers or cookies. HTTP status extraction is
limited to the known upstream printf literal on Windows x64. Selected error
formats produce fixed diagnostic categories. HTTP 429, 405 and 5xx stop the attempt when reported by the native
HTTP callback. Terminal 403 responses and recognized login-limit notices have
specific messages. An HTML MFA form with input fields
can be shown after HTTP 401 or 403. A 403 containing a username/password form
ends the attempt. OpenConnect reuses identifiers for HTML and
tokeninfo challenges, so the app allows these forms within the six-step limit
per category. Repeated forms with a specific ID and the same input fields end
the attempt and suggest waiting about two minutes before reconnecting. The actual
lockout duration depends on the gateway configuration. FortiClient can display
details when OpenConnect exposes only a repeated form or an error code.
Submitting a form does not confirm login. After an unexpected disconnect with
pending network changes, restore the network before starting a new connection;
Connect stays disabled until recovery completes. The app does not promise an
unlimited session duration: the server can reject an existing session.
OpenConnect exit 2 is reported as a rejected VPN session after authentication,
not as an invalid password/OTP. `vpn-exit.json` retains only the exit code, fixed
phase/reason and timestamp; unknown exit codes are not assigned an invented cause.
Do not publish sessions, profiles, RDP files, dumps or screenshots containing work data.

Public export audit:

    python audit_public.py .

See SECURITY.md, THIRD-PARTY.md and REVIEW.md. No remote publication is performed by build tools.

## Repository layout

Run all commands above from the `windows/` directory. Current projects are
`FortiSplit.Work/` and `FortiSplit.Work.Checks/`. OpenConnect runtime binaries
are supplied separately; source CI does not connect a VPN.
The older FortiClient-based client is documented in [COMPANION.md](COMPANION.md).
Its previous review is [COMPANION-REVIEW.md](COMPANION-REVIEW.md).
