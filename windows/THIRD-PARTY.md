# Third-party runtime

OpenConnect and related libraries are separate, unmodified runtime dependencies.
Their binaries are not included in the public source export. When distributing a binary
package, preserve their license notices and satisfy the applicable source/relinking
requirements. This source preparation does not publish a binary release.

- OpenConnect: https://www.infradead.org/openconnect/
- Fortinet support: https://www.infradead.org/openconnect/fortinet.html
- API header, version 9.12: https://gitlab.com/openconnect/openconnect/-/blob/v9.12/openconnect.h
- Wintun: https://www.wintun.net/

The native binding targets the Windows x64 OpenConnect 9.12 ABI. Library files must be
obtained from a trusted distribution. Do not replace them with files from unknown sources.
