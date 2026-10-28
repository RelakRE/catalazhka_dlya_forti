# Review: version 1.2.1

- RD Gateway target resolution is delegated to the gateway. Detect mode retains
  optional direct routes only when target DNS succeeds; required gateway and direct
  RDP DNS failures still block readiness. Mode 4 correctly remains direct RDP.
- Offline regression checks cover a missing gateway-only target, required target
  failure, successful readiness through the gateway, and absence of stale target NRPT.

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
- UI, worker, watcher and owned-network cleanup retain their separate roles.
- A hidden technical console is used only for graceful CLI cancellation. Authentication
  itself is rendered by the app. A real gateway login remains a required integration test.
- The native ABI, Windows vault, IPC and UI are tested offline. They do not establish
  successful server authentication or a TrueConf call.

No remote repository was created or published. A second independent reviewer was not used.
