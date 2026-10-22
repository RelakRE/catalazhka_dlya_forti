"""Fixed paths and protocol for the optional, per-user root route helper."""
import ctypes
import hashlib
import os
from pathlib import Path
import stat

API_VERSION = 1
ROOT_MODULES = ("route_probe_helper.py", "split_tunnel_helper.py", "service_paths.py", "privileged_service.py", "json_codec.py")
INSTALL_BASE = Path("/Library/PrivilegedHelperTools/local.fortisplit.helper")


def label(uid):
    return "local.fortisplit.helper." + str(int(uid))


def install_path(uid):
    return INSTALL_BASE / str(int(uid))


def socket_directory(uid):
    return Path("/var/run") / ("forti-split-helper-" + str(int(uid)))


def socket_path(uid):
    return socket_directory(uid) / "service.sock"


def peer_uid(sock):
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    fn = ctypes.CDLL(None, use_errno=True).getpeereid
    fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    fn.restype = ctypes.c_int
    if fn(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid failed")
    return uid.value


def digest(directory):
    value = hashlib.sha256()
    for name in ROOT_MODULES:
        path = Path(directory) / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid helper source: " + name)
        value.update(name.encode() + b"\0" + path.read_bytes())
    runtime = Path(directory) / "runtime-manifest.json"
    if runtime.exists():
        if runtime.is_symlink() or not runtime.is_file():
            raise ValueError("Invalid runtime manifest")
        value.update(b"runtime-manifest.json\0" + runtime.read_bytes())
    return value.hexdigest()


def check_root_directory(path):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("Unsafe helper directory: " + str(path))


def worker_argv(directory, mode):
    if mode not in ("lease", "health", "recover"):
        raise ValueError("Unsupported helper mode")
    # Isolated Python; root modules are resolved ONLY from a protected directory.
    code = "import sys; sys.path.insert(0, {!r}); import split_tunnel_helper; sys.exit(split_tunnel_helper.main())".format(str(directory))
    return [python_executable(directory), "-I", "-B", "-c", code, mode]


def python_executable(directory):
    if (Path(directory) / "runtime-manifest.json").is_file():
        return str(Path(directory) / "runtime/bin/python3.12")
    return "/usr/bin/python3"  # Legacy CLI/source deployments only.
