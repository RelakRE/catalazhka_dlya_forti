# Forti Split for Windows

Desktop client for Fortinet SSL VPN using OpenConnect. Work services use host routes
through the VPN; the normal internet connection keeps its default route.

The UI provides connect/disconnect, RDP and TrueConf launch, tray status, profile
import/export and recovery. Login, password and second-factor forms appear in the app.
Passwords are saved only when requested, in Windows Credential Manager. OTP values
and session cookies are never saved in profiles or logs.

## Build

Windows x64, .NET SDK 10 and Windows PowerShell 5.1 are required.

    dotnet restore FortiSplit.Work/FortiSplit.Work.csproj
    dotnet publish FortiSplit.Work/FortiSplit.Work.csproj -c Release --no-restore -o build/FortiSplit-1.2.0
    dotnet run --project FortiSplit.Work.Checks -c Release
    powershell.exe -NoProfile -File test_work_network.ps1
    python -m unittest test_windows_work

Supply the unmodified OpenConnect 9.12 Windows runtime in the output's `client`
directory: openconnect.exe, libopenconnect-5.dll and its dependent DLLs, wintun.dll,
and the associated license files. Runtime binaries are excluded from this source tree.
`prepare-work.ps1 -ClientDirectory <local-runtime-directory>` can copy a local runtime.

## Profiles

`profile.example.json` contains documentation-only placeholders. Set your real VPN
server, local RDP file and optional TrueConf settings in the app or import a private
JSON profile. Existing profiles under `%LOCALAPPDATA%\Forti Split Work` are reused.
Private profile exports end in `.local.json` and must stay outside Git.

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
