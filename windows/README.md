# Forti Split for Windows

Desktop client for Fortinet SSL VPN using OpenConnect. Work services use host routes
through the VPN; the normal internet connection keeps its default route.

The UI provides connect/disconnect, RDP and TrueConf launch, tray status, profile
import/export and recovery. Login, password and second-factor forms appear in the app.
Passwords are saved only when requested, in Windows Credential Manager. OTP values
and session cookies are never saved in profiles or logs.

## Download and first launch

Download the Windows preview from [Releases](https://github.com/RelakRE/catalazhka_dlya_forti/releases/tag/windows-v1.2.4).
Extract the complete archive and run `Forti Split.exe`. .NET is included.
The first launch downloads and prepares upstream OpenConnect 9.21 and Wintun 0.14.1
in a progress window, without a console. Internet and a writable app folder are
required. Executable downloads are checked against pinned SHA256 values before use.
Existing complete runtimes are reused. See [release notes](RELEASE-NOTES.md).

## Build from source

Windows x64, .NET SDK 10 and Windows PowerShell 5.1 are required.

    dotnet restore FortiSplit.Work/FortiSplit.Work.csproj
    dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release --no-restore -o build/FortiSplit-1.2.4
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

The private network profile should include known gateway IPv4 addresses in
`ExtraHosts` and private DNS suffixes (without a leading dot) in `DnsDomains`.
Those IP routes and domain DNS policies are installed before any tunnel DNS query,
and the DNS cache is cleared once. This follows the WorkVPN bootstrap approach:
the first failed DNS lookup cannot prevent the gateway routes or domain policy
from being installed. No per-PC allowlist is required for RDP through that gateway.
Use the network administrator's actual values; public examples remain blank.
Import the updated private profile, then set your own username and local RDP file.

The app does not approve or reject RDP destination names or pre-test RDP ports.
Any selected local RDP file is passed unchanged to mstsc, including short computer
names and system gateway profiles. Recognizable endpoints are best-effort route
hints only. DNS failure for a target, gateway or other work endpoint does not stop
the authenticated VPN tunnel; actual RDP errors are handled by the Windows client.
Work routes and DNS are configured once on connection and on an actual OpenConnect
reconnect. There are no periodic network diagnostics, internet probes or watchdog.
Normal Disconnect/Exit removes the session's settings. After a crash or unexpected
disconnect, press Restore Network: it stops only the recorded VPN process and removes
the app's own settings. Existing profiles and private credentials are reused.

For a fresh installation, open Settings, expand Advanced, set the VPN server and select
the RDP file. Configure TrueConf if needed. Password/OTP are entered at connection time.
Disconnect FortiClient before using this app. A UAC prompt starts the network worker.
The UI and launched work apps retain ordinary user rights.

## Verification limits

Offline tests cover configuration, native ABI initialization, Credential Manager,
private IPC and mocked network setup/recovery. They do not prove compatibility with
every gateway or successful RDP login/video calls. A real login requires user credentials.
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
