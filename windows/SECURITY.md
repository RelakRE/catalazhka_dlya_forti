# Credentials and local data

- Windows Credential Manager stores an optional VPN password scoped to the exact
  server URL and username. Unchecking Remember Password and saving deletes that entry.
- Password saving occurs only after successful authentication. Ambiguous challenge
  answers and OTPs are not eligible for saving.
- The elevated worker and UI exchange bounded messages over a current-user named pipe.
  Both sides verify the peer PID. Plaintext responses exist transiently in process memory.
- The first UAC-approved run of a build installs its worker and embedded network
  scripts under `Program Files\Forti Split Network`. The worker prepares the VPN
  runtime from archives verified against pinned SHA-256 values and checks installed
  files against a protected manifest on subsequent connections.
- Administrators and SYSTEM control the installed files, recovery journals and
  machine-wide files that serialize VPN and network operations.
  The worker reads configuration and requests from LocalAppData and writes status,
  logs and session files in Program Files. The desktop account can read its own
  session output. The protected recovery journal records the tunnel adapter GUID.
- Authentication cookies are passed to OpenConnect over stdin, never in argv or files.
  Console output is drained without logging. Native library progress text is discarded;
  only validated numeric HTTP status codes and fixed authentication events are retained.
- TLS validation failures are rejected. The app provides no trust-bypass checkbox.
- The app checks the VPN hostname and port before showing or submitting every
  authentication form. Automatic updates require a Sigstore attestation from
  the pinned project workflow on GitHub Actions, or a publisher signature that
  matches the public key embedded in the installed build. The updater checks the
  launched executable against the verified archive and retains the proof for later launches.
  When a legacy installer discards the archive, the updated app verifies a separate
  attestation or publisher signature over the locked executable before confirming
  the update and when opening it for worker installation.
- The Work tab uses the IPv4 addresses and packet lengths observed on the VPN
  interface to count traffic to configured work IPs. Packet contents are discarded.
  The private session status contains the currently active work IPs, their names,
  aggregate counters, rates, and activity intervals. It also retains the five most
  recent completed intervals with address and timestamps.
- Route, ICMP and TCP checks run on request for one chosen IPv4. ICMP and TCP are
  attempted only for VPN routes, with the VPN source address. Normal Disconnect/Exit
  removes session changes. After an unexpected failure, use Restore Network; until
  then, recorded routes, DNS, filters and a remaining VPN process can persist.
  An elevated administrator can recover protected journals across accounts.
  Recovery checks the recorded PID, creation time and executable path before
  stopping a process.
- During reconnect, packet filters block traffic to known work IPv4 and VPN DNS
  servers on other interfaces. The protected journal tracks the filters for cleanup.
- The IPv4-only tunnel also blocks IPv6 destinations observed in VPN DNS AAAA
  answers for configured work names. Coverage follows the addresses observed
  during setup, retries, reconnect and explicit updates.
- Profiles and session reports contain private names, IPs and local paths.
  Keep these and the protected recovery journal out of Git. A private export is not encrypted.
- Live work-address updates accept a bounded hostname/IPv4 and DNS-domain request.
  Route refresh removes only recorded session-owned routes and preserves shared IPs.
  The worker reports success after routes, DNS, filters and the session config commit.
- Initial installation of each worker build trusts the app package approved in UAC.

Only the contents of the audited public export should be published. Existing local
archives, older builds and research notes belong in ignored private storage.
