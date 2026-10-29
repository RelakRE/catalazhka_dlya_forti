# Credentials and local data

- Windows Credential Manager stores an optional VPN password scoped to the exact
  server URL and username. Unchecking Remember Password and saving deletes that entry.
- Password saving occurs only after successful authentication. Ambiguous challenge
  answers and OTPs are not eligible for saving.
- The elevated worker and UI exchange bounded messages over a current-user named pipe.
  Both sides verify the peer PID. Plaintext responses exist transiently in process memory.
- Authentication cookies are passed to OpenConnect over stdin, never in argv or files.
  Console output is drained without logging. Native library progress text is discarded;
  only validated numeric HTTP status codes and fixed authentication events are retained.
- TLS validation failures are rejected. The app provides no trust-bypass checkbox.
- Network self-diagnostics and watchdog recovery are disabled. Normal Disconnect/Exit
  removes session changes. After an unexpected failure, use Restore Network; until
  then, recorded routes/DNS settings and a remaining VPN process can persist.
  Manual recovery checks the recorded PID, creation time and executable path before
  stopping that process and removes only network settings owned by this app.
- Profiles and session recovery metadata contain private names, IPs and local paths.
  They live in LocalAppData and must not be committed. A private export is not encrypted.
- Live work-address updates use a bounded hostname/IPv4 and DNS-domain request under
  the private session directory. They cannot replace authentication or run commands.
  Route refresh removes only recorded session-owned routes and preserves shared IPs.
- This portable app trusts its runtime and current user. It is not a hardened service
  against a local administrator. Stop the VPN before replacing runtime files.

Only the contents of the audited public export should be published. Existing local
archives, older builds and research notes belong in ignored private storage.
