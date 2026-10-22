#!/usr/bin/python3
"""Build the local AppKit app; no system installation and no route changes."""
import argparse
import json
import os
import platform
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

import service_paths
import bundle_runtime

ROOT = Path(__file__).resolve().parent
APP = ROOT / "dist/Forti Split Intel.app"


def sign(path, identity):
    args = ["/usr/bin/codesign", "--force", "--sign", identity]
    args += ["--timestamp=none"] if identity == "-" else ["--timestamp", "--options", "runtime"]
    subprocess.run(args + [str(path)], check=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-archive", type=Path)
    parser.add_argument("--identity", default="-", help="Developer ID identity, or '-' for a clearly labelled ad-hoc test build")
    parser.add_argument("--output", type=Path, default=APP)
    args = parser.parse_args()
    if platform.machine() != "x86_64":
        raise SystemExit("This release supports Intel build hosts only.")
    if args.output.exists():
        raise SystemExit("Output already exists. Select a new --output path; existing applications are not overwritten.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".forti-build-", dir=str(args.output.parent)))
    application = stage / "Forti Split.app"
    contents = application / "Contents"
    binaries = contents / "MacOS"
    resources = contents / "Resources"
    binaries.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)
    modules = ("split_tunnel.py", "route_probe.py", "vpn_diagnostics.py", "gui_backend.py", "service_client.py", "install_helper.py", "profile_store.py") + service_paths.ROOT_MODULES
    for name in modules:
        shutil.copy2(ROOT / name, resources / name)
    # A release NEVER embeds the developer's private working profile.
    (resources / "split-config.json").write_text(json.dumps({"schema": 1, "session_minutes": 0, "work_ipv4": []}) + "\n")
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", resources)
    runtime = bundle_runtime.obtain(args.runtime_archive)
    shutil.copytree(runtime, resources / "runtime")
    magic = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
    # Sign every nested interpreter, extension and dylib before sealing the app.
    for path in sorted((resources / "runtime").rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                executable = stream.read(4) in magic
            if executable:
                sign(path, args.identity)
    (resources / "runtime-manifest.json").write_text(json.dumps(bundle_runtime.manifest(resources / "runtime"), sort_keys=True))
    (resources / "helper-manifest.json").write_text(json.dumps({"api": service_paths.API_VERSION, "digest": service_paths.digest(resources)}, indent=2))
    info = {"CFBundleName": "Forti Split", "CFBundleDisplayName": "Forti Split", "CFBundleExecutable": "FortiSplit",
            "CFBundleIdentifier": "local.fortisplit.desktop", "CFBundleVersion": "1.2.0",
            "CFBundleShortVersionString": "1.2.0", "CFBundlePackageType": "APPL", "LSMinimumSystemVersion": "13.0",
            "NSHighResolutionCapable": True, "NSPrincipalClass": "NSApplication"}
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    cache = ROOT / "build/swift-cache"
    cache.mkdir(parents=True, exist_ok=True)
    flags = []
    # This Mac's CLT contains both the obsolete and current SwiftBridging
    # module maps. Hide ONLY the obsolete duplicate in the compiler's virtual
    # filesystem. No SDK/CLT/system file is edited or removed.
    legacy = Path("/Library/Developer/CommandLineTools/usr/include/swift/module.modulemap")
    current = legacy.with_name("bridging.modulemap")
    if legacy.is_file() and current.is_file() and "module SwiftBridging" in legacy.read_text() and "module SwiftBridging" in current.read_text():
        empty = ROOT / "build/obsolete-swift-bridging.modulemap"
        empty.write_text("// Duplicate legacy module map hidden for this build only.\n")
        overlay = ROOT / "build/swift-overlay.json"
        overlay.write_text(json.dumps({"version": 0, "roots": [{"type": "file", "name": str(legacy), "external-contents": str(empty)}]}))
        flags = ["-vfsoverlay", str(overlay), "-Xcc", "-ivfsoverlay", "-Xcc", str(overlay)]
    subprocess.run(["/usr/bin/xcrun", "swiftc", "-swift-version", "5", "-parse-as-library", "-O",
                    "-target", "x86_64-apple-macos13.0",
                    "-module-cache-path", str(cache)] + flags + ["-framework", "AppKit", str(ROOT / "FortiSplitApp.swift"),
                    "-o", str(binaries / "FortiSplit")], check=True)
    sign(application, args.identity)
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(application)], check=True)
    os.rename(application, args.output)
    stage.rmdir()
    print(args.output)


if __name__ == "__main__":
    main()
