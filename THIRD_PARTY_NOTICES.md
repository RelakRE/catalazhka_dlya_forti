# Third-party runtime

The Intel application includes CPython 3.12.15 from Astral's
[python-build-standalone](https://github.com/astral-sh/python-build-standalone),
release 20261021. The source archive URL and its SHA-256 are pinned in
`runtime-lock.json`. No Python runtime is downloaded at application launch.

CPython and its bundled dependencies retain their own licenses and notices.
The complete runtime, including its license texts, is included without stripping
license files at `Forti Split.app/Contents/Resources/runtime/`.
See `runtime/lib/python3.12/LICENSE.txt`, `runtime/licenses/`, and the license/notice files in
the standard library and bundled packages. These third-party licenses are
independent of the Forti Split source code.

FortiClient, Windows App and TrueConf are not included. Their names belong to
their respective owners. This project is not affiliated with those vendors.
