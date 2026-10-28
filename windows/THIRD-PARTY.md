# Third-party runtime

The application release includes the .NET runtime and its license notices under
`licenses/`. OpenConnect, Wintun and archive tools are not redistributed in the
application ZIP. On first launch the end user's application downloads upstream
distributions directly, checks their pinned SHA256 values, extracts the required
runtime files locally and deletes temporary archive tools. The source and download
URLs and hashes are recorded in `FortiSplit.Work/RuntimeSetup.cs`.

Downloaded components: OpenConnect 9.21 (LGPL 2.1 and component licenses), its
unmodified upstream Windows runtime dependencies, Wintun 0.14.1 (upstream signed
binary license in its ZIP, retained as `client/WINTUN-LICENSE.txt`), and temporary
7-Zip 24.09 tools (upstream licenses, https://www.7-zip.org/license.txt).
Upstream source: https://gitlab.com/openconnect/openconnect/-/tree/v9.21,
https://git.zx2c4.com/wintun/, https://github.com/ip7z/7zip/tree/24.09.
No restriction on replacing compatible runtime libraries is imposed by the app.

- OpenConnect: https://www.infradead.org/openconnect/
- Fortinet support: https://www.infradead.org/openconnect/fortinet.html
- API header, version 9.12: https://gitlab.com/openconnect/openconnect/-/blob/v9.12/openconnect.h
- Wintun: https://www.wintun.net/

The native binding targets the Windows x64 OpenConnect 9.12 public ABI, checked with 9.21. Library files must be
obtained from a trusted distribution. Do not replace them with files from unknown sources.
