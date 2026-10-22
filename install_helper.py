#!/usr/bin/python3
"""Explicit one-time admin installer. Never installs sudoers rules or passwords."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import stat
import subprocess
import tempfile

MODULES = ("route_probe_helper.py", "split_tunnel_helper.py", "service_paths.py", "privileged_service.py")
BASE = Path("/Library/PrivilegedHelperTools/local.fortisplit.helper")


def protected_directory(path):
    path.mkdir(mode=0o755, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("Небезопасный системный каталог: " + str(path))


def atomic_write(path, contents, mode):
    if path.is_symlink():
        raise PermissionError("Не заменяется символическая ссылка: " + str(path))
    fd, temporary = tempfile.mkstemp(prefix=".forti-install-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def payload(source):
    data = {}
    digest = hashlib.sha256()
    for name in MODULES:
        path = source / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
            raise ValueError("Недопустимый исходник помощника: " + name)
        contents = path.read_bytes()
        data[name] = contents
        digest.update(name.encode() + b"\0" + contents)
    runtime = source / "runtime-manifest.json"
    if runtime.exists():
        if runtime.is_symlink() or runtime.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Invalid runtime manifest")
        contents = runtime.read_bytes()
        data["runtime-manifest.json"] = contents
        digest.update(b"runtime-manifest.json\0" + contents)
        listing = runtime_listing(contents)
        for name, entry in listing.items():
            path = source / "runtime" / name
            # Disallow a linked file OR parent directory, including the runtime root.
            current = path
            while current != source:
                if current.is_symlink():
                    raise ValueError("Linked runtime payload")
                current = current.parent
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != entry["size"]:
                raise ValueError("Invalid runtime payload: " + name)
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise ValueError("Runtime checksum mismatch: " + name)
            data["runtime/" + name] = content
    expected = json.loads((source / "helper-manifest.json").read_text())
    if expected.get("digest") != digest.hexdigest() or expected.get("api") != 1:
        raise ValueError("Проверка целостности установочного пакета не прошла.")
    data["helper-manifest.json"] = json.dumps(expected).encode()
    return data


def runtime_listing(contents):
    value = json.loads(contents)
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("files"), dict):
        raise ValueError("Invalid runtime manifest")
    files = value["files"]
    if not 1 <= len(files) <= 20000 or "bin/python3.12" not in files:
        raise ValueError("Runtime interpreter missing")
    total = 0
    for name, entry in files.items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name or not path.parts:
            raise ValueError("Unsafe runtime path")
        if (not isinstance(entry, dict) or type(entry.get("size")) is not int
                or not 0 <= entry["size"] <= 50 * 1024 * 1024
                or type(entry.get("executable")) is not bool
                or not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in entry["sha256"])):
            raise ValueError("Invalid runtime entry")
        total += entry["size"]
    if total > 300 * 1024 * 1024 or not files["bin/python3.12"]["executable"]:
        raise ValueError("Invalid runtime size/interpreter")
    return files


def clear_runtime(directory):
    """Only remove a previously recorded, root-owned runtime. Unknown files block removal."""
    runtime = directory / "runtime"
    manifest = directory / "runtime-manifest.json"
    if not runtime.exists():
        return
    protected_directory(runtime)
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_uid != 0:
        raise PermissionError("Unknown runtime left untouched")
    names = runtime_listing(manifest.read_bytes())
    actual = set()
    directories = []
    for current, folders, files in os.walk(runtime, followlinks=False):
        root = Path(current)
        protected_directory(root)
        directories.append(root)
        for name in folders:
            protected_directory(root / name)
        for name in files:
            path = root / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError("Unsafe runtime file left untouched")
            actual.add(path.relative_to(runtime).as_posix())
    if actual != set(names):
        raise PermissionError("Unknown runtime files left untouched")
    for name in names:
        (runtime / name).unlink()
    for folder in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        folder.rmdir()


def service_plist(uid, bundled=False):
    directory = BASE / str(uid)
    code = "import sys; sys.path.insert(0, {!r}); import privileged_service; privileged_service.main()".format(str(directory))
    return {"Label": "local.fortisplit.helper." + str(uid), "UserName": "root",
            "ProgramArguments": [str(directory / "runtime/bin/python3.12") if bundled else "/usr/bin/python3", "-I", "-B", "-c", code, "--uid", str(uid)],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
            "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}}


def write_payload(directory, files):
    listing = runtime_listing(files["runtime-manifest.json"]) if "runtime-manifest.json" in files else {}
    for name, contents in files.items():
        target = directory / name
        if name.startswith("runtime/"):
            for parent in reversed(target.parent.relative_to(directory).parents):
                protected_directory(directory / parent)
            protected_directory(target.parent)
        atomic_write(target, contents, 0o755 if name.startswith("runtime/") and listing[name[8:]]["executable"] else 0o644)


def remove_helper(directory):
    protected_directory(directory)
    known = set(MODULES) | {"helper-manifest.json", "runtime-manifest.json", "runtime"}
    if any(path.name not in known for path in directory.iterdir()):
        raise PermissionError("Unknown helper files left untouched")
    for path in directory.iterdir():
        if path.name != "runtime":
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError("Unsafe helper file left untouched")
    clear_runtime(directory)
    for name in MODULES + ("helper-manifest.json", "runtime-manifest.json"):
        path = directory / name
        if path.exists():
            path.unlink()
    directory.rmdir()


def launch(*arguments):
    return subprocess.run(["/bin/launchctl"] + list(arguments), check=True, capture_output=True, timeout=30)


def install_transaction(uid, files, plist, was_running):
    """Prepare and verify the complete new copy BEFORE stopping the old service."""
    directory = BASE / str(uid)
    if directory.exists() or directory.is_symlink():
        protected_directory(directory)
    old_plist = None
    if plist.exists() or plist.is_symlink():
        info = plist.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Unsafe launchd plist left untouched")
        old_plist = plist.read_bytes()
    if was_running and old_plist is None:
        raise ValueError("Действующая служба без сохранённого plist: обновление не выполняется.")
    slot = Path(tempfile.mkdtemp(prefix="." + str(uid) + "-install-", dir=str(BASE)))
    staged = slot / "new"
    protected_directory(staged)
    write_payload(staged, files)
    bundled = "runtime-manifest.json" in files
    if bundled:
        code = "import sys; sys.path.insert(0, {!r}); import privileged_service, ctypes, socket".format(str(staged))
        subprocess.run([str(staged / "runtime/bin/python3.12"), "-I", "-B", "-c", code],
                       check=True, capture_output=True, timeout=15,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    label = "system/local.fortisplit.helper." + str(uid)
    if was_running:
        launch("bootout", label)
    backup = slot / "previous"
    moved_new = False
    try:
        if directory.exists():
            os.rename(directory, backup)
        os.rename(staged, directory)
        moved_new = True
        atomic_write(plist, plistlib.dumps(service_plist(uid, bundled)), 0o644)
        launch("bootstrap", "system", str(plist))
    except Exception as failure:
        if moved_new:
            # A failed bootstrap must not leave a partially upgraded installation.
            # launchctl may have loaded the job before returning an error.
            present = subprocess.run(["/bin/launchctl", "print", label], capture_output=True, timeout=8)
            if present.returncode == 0:
                launch("bootout", label)
            os.rename(directory, staged)
        if backup.exists():
            os.rename(backup, directory)
        if old_plist is not None:
            atomic_write(plist, old_plist, 0o644)
            if was_running:
                launch("bootstrap", "system", str(plist))
        elif plist.exists():
            plist.unlink()
        raise RuntimeError("Установка не завершена; предыдущая версия восстановлена. Диагностическая копия: " + str(slot)) from failure
    if backup.exists():
        try:
            remove_helper(backup)
        except Exception:
            print("Новая служба установлена; предыдущая копия сохранена для проверки: " + str(backup))
    if not any(slot.iterdir()):
        slot.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid < 500:
        raise PermissionError("Установка требует системного разрешения администратора и UID пользователя.")
    pwd.getpwuid(args.uid)
    # Serialize against BOTH versions of the routing guardian. Do not upgrade or
    # remove the installed code during an active route session.
    fd = os.open("/var/run/forti-route-probe.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise PermissionError("Небезопасный журнал маршрутов.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        saved = os.read(fd, 131073)
        previous = json.loads(saved) if saved else {"status": "inactive"}
        if previous.get("status") != "inactive":
            raise ValueError("Сначала выполните откат/восстановление предыдущего сеанса.")
        files = {} if args.remove else payload(args.source)
        label = "local.fortisplit.helper." + str(args.uid)
        plist = Path("/Library/LaunchDaemons") / (label + ".plist")
        directory = BASE / str(args.uid)
        existing = subprocess.run(["/bin/launchctl", "print", "system/" + label], capture_output=True, timeout=8)
        if args.remove:
            if existing.returncode == 0:
                launch("bootout", "system/" + label)
            if directory.exists():
                protected_directory(BASE)
                remove_helper(directory)
            if plist.exists():
                if plist.is_symlink() or plist.stat().st_uid != 0:
                    raise PermissionError("Неизвестный launchd plist оставлен.")
                plist.unlink()
            print("Системный помощник удалён; исходники, отчёты и FortiClient сохранены.")
        else:
            protected_directory(Path("/Library/PrivilegedHelperTools"))
            protected_directory(BASE)
            install_transaction(args.uid, files, plist, existing.returncode == 0)
            print("Системный помощник установлен. Пароли не сохраняются; sudoers не менялся.")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
