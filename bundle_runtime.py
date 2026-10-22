"""Fetch a pinned, checksum-verified Intel runtime. No installer or network at app launch."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parent
LICENSE_COMMIT = "0c5e581b54a4736cdbbe68bdd6d7e571a1dca11e"
LICENSE_NAMES = ("LICENSE", "LICENSE.bdb.txt", "LICENSE.bzip2.txt", "LICENSE.cpython.txt", "LICENSE.expat.txt",
                 "LICENSE.libX11.txt", "LICENSE.libXau.txt", "LICENSE.libedit.txt", "LICENSE.libffi.txt",
                 "LICENSE.liblzma.txt", "LICENSE.libuuid.txt", "LICENSE.libxcb.txt", "LICENSE.mpdecimal.txt",
                 "LICENSE.ncurses.txt", "LICENSE.openssl-3.txt", "LICENSE.sqlite.txt", "LICENSE.tcl.txt",
                 "LICENSE.tix.txt", "LICENSE.zlib-ng.txt", "LICENSE.zlib.txt", "LICENSE.zstd.txt")


def licenses(destination):
    cache = ROOT / "build/runtime-licenses" / LICENSE_COMMIT
    cache.mkdir(parents=True, exist_ok=True)
    def fetch(name):
        path = cache / name
        if not path.exists():
            url = "https://raw.githubusercontent.com/astral-sh/python-build-standalone/" + LICENSE_COMMIT + "/" + name
            with urllib.request.urlopen(url, timeout=30) as source:
                data = source.read(1024 * 1024 + 1)
            if not data or len(data) > 1024 * 1024:
                raise ValueError("Unexpected license document")
            path.write_bytes(data)
        return path
    with ThreadPoolExecutor(max_workers=6) as executor:
        files = list(executor.map(fetch, LICENSE_NAMES))
    target = destination / "licenses"
    target.mkdir()
    for path in files:
        shutil.copy2(path, target / path.name)


def extract(archive, destination):
    # Copy regular contents, resolving archive links in memory. Never create
    # links/devices or let tar write paths outside the dedicated directory.
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 20000:
            raise ValueError("Unexpected runtime archive size")
        total = 0
        seen = set()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "python":
                raise ValueError("Unsafe runtime archive path")
            if member.isdir():
                continue
            if not (member.isfile() or member.issym() or member.islnk()):
                raise ValueError("Unexpected runtime archive member")
            relative = Path(*name.parts[1:])
            if not relative.parts or relative in seen:
                raise ValueError("Duplicate runtime file")
            seen.add(relative)
            with bundle.extractfile(member) as stream:
                data = stream.read(50 * 1024 * 1024 + 1)
            total += len(data)
            if len(data) > 50 * 1024 * 1024 or total > 300 * 1024 * 1024:
                raise ValueError("Unexpected runtime payload size")
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if member.mode & 0o111 or str(relative) == "bin/python3.12" else 0o644)


def manifest(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("Runtime must not contain symbolic links")
        if path.is_file():
            data = path.read_bytes()
            result[path.relative_to(directory).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                "executable": bool(path.stat().st_mode & 0o111)}
    if "bin/python3.12" not in result:
        raise ValueError("Runtime interpreter missing")
    return {"schema": 1, "files": result}


def obtain(archive=None):
    lock = json.loads((ROOT / "runtime-lock.json").read_text())
    cache = ROOT / "build/runtime-download"
    cache.mkdir(parents=True, exist_ok=True)
    archive = Path(archive) if archive else cache / "python-intel.tar.gz"
    if not archive.exists():
        request = urllib.request.Request(lock["url"], headers={"User-Agent": "Forti-Split-build"})
        with urllib.request.urlopen(request, timeout=60) as source, archive.open("wb") as target:
            shutil.copyfileobj(source, target)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock["sha256"]:
        raise ValueError("Python archive SHA-256 mismatch; no runtime is built")
    stage = Path(tempfile.mkdtemp(prefix="runtime-", dir=str(cache)))
    extract(archive, stage)
    licenses(stage)
    return stage


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    print(obtain(args.archive))
