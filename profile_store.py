"""Private, strictly validated address profiles; never contains a VPN credential."""
import json
import os
from pathlib import Path
import stat
import tempfile

from profile_model import MAX_BYTES, parse


def secure_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError("Каталог данных должен быть обычной папкой текущего пользователя.")
    path.chmod(0o700)
    return path


def read(path, allow_empty=False):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("Выберите обычный JSON-файл профиля размером до 64 КБ.")
        data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Слишком большой профиль.")
    return parse(data.decode("utf-8"), allow_empty=allow_empty)


def save(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".profile-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
