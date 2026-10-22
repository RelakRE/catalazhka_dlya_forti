"""Private, strictly validated address profiles; never contains a VPN credential."""
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile

MAX_BYTES = 65536


def parse(text, allow_empty=False):
    value = json.loads(text)
    if not isinstance(value, dict) or set(value) != {"schema", "session_minutes", "work_ipv4"}:
        raise ValueError("Профиль должен содержать только schema, session_minutes и work_ipv4.")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("Неизвестная версия профиля.")
    minutes = value["session_minutes"]
    if type(minutes) is not int or not 0 <= minutes <= 480:
        raise ValueError("session_minutes: 0 — без лимита, либо от 1 до 480 минут.")
    work = value["work_ipv4"]
    if not isinstance(work, list) or not (0 if allow_empty else 1) <= len(work) <= 128:
        raise ValueError("Импортируйте профиль с 1–128 рабочими IPv4-адресами.")
    addresses = []
    for item in work:
        if not isinstance(item, str):
            raise ValueError("Адреса должны быть строками IPv4, без подсетей и команд.")
        address = ipaddress.IPv4Address(item)
        if (address.is_loopback or address.is_multicast or address.is_link_local
                or address.is_unspecified or address.is_reserved):
            raise ValueError("В профиле разрешены только обычные рабочие IPv4-адреса.")
        addresses.append(str(address))
    if len(set(addresses)) != len(addresses):
        raise ValueError("Профиль содержит повторяющиеся адреса.")
    return {"schema": 1, "session_minutes": minutes, "work_ipv4": sorted(addresses)}


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
