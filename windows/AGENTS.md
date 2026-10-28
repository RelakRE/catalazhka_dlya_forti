# Forti Split Windows

- Current source: FortiSplit.Work. Read README.md and SECURITY.md.
- Keep real hosts, usernames, paths and recovery reports outside public source.
- Config defaults and tests use documentation-only examples.
- Passwords may be stored only with explicit user opt-in, through Windows Credential Manager.
- Never store OTP/cookies or log authentication replies. Keep TLS validation enabled.
- Build/setup/offline tests must not connect a real VPN.
- Preserve journaled recovery and current-user IPC peer checks.
- Publish only the audited public export. Do not push without a direct user request.
