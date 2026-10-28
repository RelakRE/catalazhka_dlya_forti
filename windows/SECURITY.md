# Credentials and local data

- Windows Credential Manager stores an optional VPN password scoped to the exact
  server URL and username. Unchecking Remember Password and saving deletes that entry.
- Password saving occurs only after successful authentication. Ambiguous challenge
  answers and OTPs are not eligible for saving.
- The elevated worker and UI exchange bounded messages over a current-user named pipe.
  Both sides verify the peer PID. Plaintext responses exist transiently in process memory.
- Authentication cookies are passed to OpenConnect over stdin, never in argv or files.
  Console output is drained without logging. Native library progress text is discarded.
- TLS validation failures are rejected. The app provides no trust-bypass checkbox.
- Profiles and session recovery metadata contain private names, IPs and local paths.
  They live in LocalAppData and must not be committed. A private export is not encrypted.
- This portable app trusts its runtime and current user. It is not a hardened service
  against a local administrator. Stop the VPN before replacing runtime files.

Only the contents of the audited public export should be published. Existing local
archives, older builds and research notes belong in ignored private storage.
