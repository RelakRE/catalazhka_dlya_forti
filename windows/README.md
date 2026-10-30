# Forti Split for Windows

Desktop client for Fortinet SSL VPN using OpenConnect. Work services use host routes
through the VPN; the normal internet connection keeps its default route.

The UI provides connect/disconnect, RDP and TrueConf launch, tray status, profile
import/export and recovery. Login, password and second-factor forms appear in the app.
Passwords are saved only when requested, in Windows Credential Manager. OTP values
and session cookies are never saved in profiles or logs.

## Download and first launch

Download the Windows preview from [Releases](https://github.com/RelakRE/catalazhka_dlya_forti/releases/tag/windows-v1.2.6).
Extract the complete archive and run `Forti Split.exe`. .NET is included.
The first launch downloads and prepares upstream OpenConnect 9.21 and Wintun 0.14.1
in a progress window, without a console. Internet and a writable app folder are
required. Executable downloads are checked against pinned SHA256 values before use.
Existing complete runtimes are reused. See [release notes](RELEASE-NOTES.md).

## Build from source

Windows x64, .NET SDK 10 and Windows PowerShell 5.1 are required.

    dotnet restore FortiSplit.Work/FortiSplit.Work.csproj
    dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release --no-restore -o build/FortiSplit-1.2.6
    dotnet run --project FortiSplit.Work.Checks -c Release
    powershell.exe -NoProfile -File test_work_network.ps1
    python -m unittest test_windows_work

Runtime binaries are excluded from this source tree and the release archive.
The first launch prepares them from upstream automatically; `--prepare-runtime`
performs only that preparation for automation, without connecting VPN.
`prepare-work.ps1 -ClientDirectory <local-runtime-directory>` can alternatively
copy an existing compatible local runtime. The native API binding supports the
OpenConnect 9.12 public ABI and is checked offline with 9.21 for this release.
Run `./build-release.ps1` in a clean checkout to create and validate release assets.

## Profiles

`profile.example.json` contains documentation-only placeholders. Set your real VPN
server, local RDP file and optional TrueConf settings in the app or import a private
JSON profile. Existing profiles under `%LOCALAPPDATA%\Forti Split Work` are reused.
Private profile exports end in `.local.json` and must stay outside Git.

`ExtraHosts` can contain DNS names, IPv4 addresses, or a mixture. In Settings,
expand Advanced and use **Рабочие сайты / имена / IPv4**: the field also accepts
full HTTP/HTTPS links and stores only their hostnames, ignoring ports and paths.
Separate entries with commas or newlines. IP addresses do not need to be known in
advance. JSON profiles retain the existing hostname/IPv4 format. Optional private
DNS suffixes in `DnsDomains` have no leading dot; each explicitly added hostname
gets its own exact DNS rule even without a suffix. Redirects to another hostname
require adding that hostname too. Resolution and host routes currently use IPv4.

VPN DNS routes, optional literal IP routes and work-name/domain DNS rules are
installed before any tunnel DNS query. DNS lookup runs after the synchronous
OpenConnect hook. Missing names get up to three additional attempts, after 3, 10
and 30 seconds from the preceding attempt. A lookup pass stops starting queries
after 15 seconds; an in-flight QuickTimeout query may finish later. Already
resolved names are skipped during these retries. An unresolved name does not
disconnect the VPN and its count appears in the connected status.

While connected, edit just the work names/DNS domains and click **Применить рабочие
адреса** to save them and resolve their current IPs without reconnecting or entering
2FA again. The elevated worker validates a bounded address-only request in the
private session directory; it cannot change the VPN server or authentication.
Replacement routes are added before obsolete session-owned routes are removed.
An IP shared by another work name or VPN DNS is retained. A temporary DNS failure
keeps that name's previous routes; deleting the name explicitly removes routes
no longer needed elsewhere. Disconnect/recovery removes all session-owned changes.
There is no continuous DNS polling or TTL-based refresh; applying addresses or
reconnecting performs a fresh lookup. Use actual internal values in private
profiles; public examples remain blank.

The app does not approve or reject RDP destination names or pre-test RDP ports.
Any selected local RDP file is passed unchanged to mstsc, including short computer
names and system gateway profiles. Recognizable endpoints are best-effort route
hints only. DNS failure for a target, gateway or other work endpoint does not stop
the authenticated VPN tunnel; actual RDP errors are handled by the Windows client.
Work routes and DNS are configured on connection, actual OpenConnect reconnect,
bounded retries of unresolved names, and explicit application of work addresses.
There are no periodic network diagnostics, internet probes or watchdog.
Normal Disconnect/Exit removes the session's settings. After a crash or unexpected
disconnect, press Restore Network: it stops only the recorded VPN process and removes
the app's own settings. Existing profiles and private credentials are reused.

For a fresh installation, open Settings, expand Advanced, set the VPN server and select
the RDP file. Configure TrueConf if needed. Password/OTP are entered at connection time.
Disconnect FortiClient before using this app. A UAC prompt starts the network worker.
The UI and launched work apps retain ordinary user rights.

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
During authentication, network waits are cancelled after 90 seconds; time spent
entering a password or MFA response in the app is not counted. A timeout permanently
ends that authentication attempt: subsequent native callbacks cannot show another
form or restart the deadline. A failed HTTP response read also stops repeated form
callbacks instead of asking for another MFA response. A private
`auth-stage.json` records only the latest fixed phase name, step number and UTC
timestamp. `auth-trace.json` retains up to 160 fixed phase/form-category events and
numeric HTTP status codes, with timestamps; neither file retains form contents,
credentials, server response bodies, headers or cookies. HTTP status extraction is
limited to the known upstream printf literal on Windows x64; other progress output
is discarded. Repeated login/challenge forms show an attempt counter, do not refill
the saved password after the first login form, and stop before a seventh form of
either category. A repeated form alone does not establish invalid credentials.
Login and confirmation dialogs explain repeated requests separately. A repeated
login request is not a password-change request; saved passwords are not filled again.
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
