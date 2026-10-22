"""OS-independent schema-1 profile domain model. No file, IPC or route operations."""
import ipaddress
from json_codec import loads

MAX_BYTES = 65536


def parse(text, allow_empty=False):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Профиль должен быть JSON UTF-8 размером до 64 КБ.")
    value = loads(text.removeprefix("\ufeff"))
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
