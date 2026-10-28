# Review: version 1.2.4

- Configured bootstrap IPv4 routes and private-domain NRPT are applied in the connect
  hook before the first lookup; no DNS query runs in the synchronous hook. Resolve
  retains those policies even when every work-name query fails. The DNS cache is
  cleared once per setup. Profile domain/IP data is private and never built in.
- A mocked regression verifies three gateway IP routes and two private-domain rules
  before any DNS call, with all work-name queries failing, plus owned-only recovery.

- Neither target nor gateway DNS/TCP checks gate the VPN. RDP is passed to mstsc
  unchanged; parsable endpoints provide best-effort route hints, without rejecting
  short names, system gateway profiles or other Windows RDP syntax.
- Offline regressions cover missing target and gateway DNS, all DNS queries failing,
  VPN readiness with unresolved names, and recovery ownership. DNS tries VPN UDP,
  VPN TCP and the Windows resolver during connection setup only.

- Username persistence roundtrip and UI form prefill are covered by tests.
- Native authentication uses public OpenConnect callbacks, not prompt scraping.
- A current-user named pipe verifies both peer PIDs and bounds messages to 64 KiB.
- Server form labels are UI-only; callback progress and CLI output are not logged.
- Password save eligibility requires a definite password field. OTP/challenge answers
  are excluded, including password-typed fields with OTP labels/messages.
- Credential writes occur only after authentication success. Disabling retention removes
  the old scoped entry. Passwords/cookies never enter profile/session JSON or argv.
- Private profiles contain real endpoints; compiled defaults are blank. Public fixtures
  use example.com and RFC 5737 IPs. Private history/builds are excluded from the export.
- There is no watcher, periodic DNS refresh, internet probe or work-check report.
  DNS setup occurs once per tunnel generation. The effective-policy overlap scan
  that caused issue #1 was removed; foreign DNS policies are never deleted.
- Normal Disconnect/Exit cleans up. Unexpected failure leaves the journal for the
  Restore Network button. Manual recovery signals a remaining session worker and
  stops only a recorded OpenConnect PID with matching creation time and image path.
- A hidden technical console is used only for graceful CLI cancellation. Authentication
  itself is rendered by the app. A real gateway login remains a required integration test.
- The native ABI, Windows vault, IPC and UI are tested offline. They do not establish
  successful server authentication or a TrueConf call.

Source and preview assets are published in the project's GitHub repository.
An independent second reviewer was not used.
