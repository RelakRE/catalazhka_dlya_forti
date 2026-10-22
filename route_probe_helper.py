#!/usr/bin/python3
"""Small root-only, time-limited guardian for exactly one IPv4 host route.

No imports from the diagnostic collector, no shell, no DNS/VPN/default-route writes.
The guardian survives the UI process: EOF on its pipe or a deadline triggers rollback.
"""

import argparse
import fcntl
import ipaddress
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
import json_codec


LOCK_FILE = "/var/run/forti-route-probe.lock"
LEASE_SECONDS = 45
PROTOCOL_VERSION = 2
HEALTH_SECONDS = 3


class ProbeError(Exception):
    pass


def execute(argv):
    try:
        completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors="replace", timeout=5,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("Команда {} не завершилась: {}".format(argv[0], type(exc).__name__))
    if completed.returncode != 0:
        # Do not return raw scutil status: SessionOptions may contain credentials.
        detail = completed.stdout.strip() if argv[0] == "/sbin/route" else ""
        raise ProbeError("Ошибка команды {} (код {}): {}".format(
            " ".join(argv), completed.returncode, detail))
    return completed.stdout


def parse_route(raw):
    fields = {}
    for key in ("destination", "gateway", "interface", "mask"):
        match = re.search(r"^\s*" + key + r":\s*(\S+)", raw, re.M)
        if match:
            fields[key] = match.group(1)
    match = re.search(r"^\s*flags:\s*<([^>]+)>", raw, re.M)
    fields["flags"] = match.group(1).split(",") if match else []
    return fields


def route_rows(raw, target):
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] in (target, target + "/32"):
            rows.append({"destination": parts[0], "gateway": parts[1],
                         "flags": parts[2], "interface": parts[3]})
    return rows


class Operations:
    def __init__(self, runner=execute):
        self.run = runner

    def route(self, target, scope=None):
        argv = ["/sbin/route", "-n", "get"]
        if scope:
            argv += ["-ifscope", scope]
        return parse_route(self.run(argv + [target]))

    def rows(self, target):
        return route_rows(self.run(["/usr/sbin/netstat", "-rn", "-f", "inet"]), target)

    def forti(self, required=True):
        listing = self.run(["/usr/sbin/scutil", "--nc", "list"])
        connected = [line for line in listing.splitlines() if "(Connected)" in line]
        forti = [line for line in connected if "com.fortinet" in line.lower()]
        if any("com.fortinet" not in line.lower() for line in connected):
            raise ProbeError("Подключён другой VPN; сначала отключите его.")
        if not required and not connected:
            return None
        if len(forti) != 1:
            raise ProbeError("Нужен один подключённый FortiClient на Mac.")
        identifier = re.search(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", forti[0])
        if not identifier:
            raise ProbeError("Не удалось определить профиль FortiClient.")
        raw = self.run(["/usr/sbin/scutil", "--nc", "status", identifier.group(0)])
        if not raw.startswith("Connected\n"):
            raise ProbeError("FortiClient уже не подключён.")
        interfaces = set(re.findall(r"InterfaceName\s*:\s*(utun\d+)", raw))
        servers = set(re.findall(r"ServerAddress\s*:\s*(\d+\.\d+\.\d+\.\d+)", raw))
        if len(interfaces) != 1 or len(servers) != 1:
            raise ProbeError("Не удалось однозначно определить интерфейс/сервер VPN.")
        if not re.search(r"vpnType\s*:\s*ssl\b", raw, re.I):
            raise ProbeError("Эта проба подготовлена для обнаруженного SSL VPN; тип сейчас другой.")
        return {"interface": interfaces.pop(), "server": servers.pop()}

    def physical(self, interface, gateway=None, source=None):
        if not re.fullmatch(r"en\d+", interface):
            raise ProbeError("Разрешён только физический интерфейс enN.")
        route = self.route("default", interface)
        current_gateway = route.get("gateway", "")
        try:
            ipaddress.IPv4Address(current_gateway)
        except ValueError:
            raise ProbeError("Не найден обычный IPv4-шлюз текущей сети.")
        if route.get("interface") != interface or (gateway and gateway != current_gateway):
            raise ProbeError("Физический интерфейс или шлюз изменился; подготовку нужно обновить без VPN.")
        raw = self.run(["/sbin/ifconfig", interface])
        addresses = re.findall(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\b", raw, re.M)
        if "status: active" not in raw or not addresses or (source and source not in addresses):
            raise ProbeError("Физическая сеть/IPv4-адрес изменились или интерфейс неактивен.")
        if self.route(current_gateway).get("interface") != interface:
            raise ProbeError("Обычный шлюз сейчас не достигается через физический интерфейс.")
        return {"interface": interface, "gateway": current_gateway,
                "source": source if source else addresses[0]}


def validate_spec(spec):
    target = ipaddress.IPv4Address(spec["target"])
    gateway = ipaddress.IPv4Address(spec["gateway"])
    source = ipaddress.IPv4Address(spec["source"])
    if not target.is_global or str(target) in (str(gateway), str(source)):
        raise ProbeError("Проба допускает только один публичный IPv4, отличный от локального адреса и шлюза.")
    if not re.fullmatch(r"en\d+", spec["interface"]):
        raise ProbeError("Некорректный физический интерфейс.")
    if not re.fullmatch(r"utun\d+", spec["vpn_interface"]):
        raise ProbeError("Некорректный интерфейс VPN.")


def owned_rows(rows, spec):
    return [row for row in rows if row["gateway"] == spec["gateway"]
            and row["interface"] == spec["interface"] and "H" in row["flags"]
            and "S" in row["flags"] and "G" in row["flags"] and "I" not in row["flags"]]


class RouteLease:
    def __init__(self, spec, ops=None, journal=None):
        validate_spec(spec)
        self.spec = spec
        self.ops = ops or Operations()
        self.journal = journal or (lambda value: None)
        self.armed = False
        self.actions = []

    def begin(self):
        spec = self.spec
        context = self.ops.forti()
        if context["interface"] != spec["vpn_interface"] or context["server"] == spec["target"]:
            raise ProbeError("Интерфейс VPN изменился либо тестовый IP совпал с VPN-сервером.")
        self.ops.physical(spec["interface"], spec["gateway"], spec["source"])
        before = self.ops.route(spec["target"])
        if before.get("interface") != spec["vpn_interface"]:
            raise ProbeError("Тестовый IP уже идёт вне текущего VPN; маршрут не изменён.")
        existing = self.ops.rows(spec["target"])
        # Never remove/replace static or otherwise explicit host routes, on any scope.
        if any("S" in row["flags"] or "W" not in row["flags"] for row in existing):
            raise ProbeError("Для тестового IP уже есть отдельный не-кешированный маршрут; проба остановлена.")
        self.armed = True
        self.journal({"status": "armed", "spec": spec, "owner": int(os.environ.get("SUDO_UID", os.getuid()))})
        # A successful pre-test can have created a scoped kernel clone. Deleting this
        # disposable clone does not remove its parent route; lookup rebuilds it later.
        for row in existing:
            if row["interface"] != spec["vpn_interface"]:
                continue
            argv = ["/sbin/route", "-n", "delete", "-host"]
            if "I" in row["flags"]:
                argv += ["-ifscope", row["interface"]]
            argv.append(spec["target"])
            self.actions.append({"argv": argv, "output": self.ops.run(argv)})
        argv = ["/sbin/route", "-n", "add", "-host", spec["target"], spec["gateway"]]
        self.actions.append({"argv": argv, "output": self.ops.run(argv)})
        if not owned_rows(self.ops.rows(spec["target"]), spec):
            raise ProbeError("Добавленный маршрут не подтверждён в таблице.")
        effective = self.ops.route(spec["target"])
        if effective.get("interface") != spec["interface"] or effective.get("gateway") != spec["gateway"]:
            raise ProbeError("Эффективный маршрут остался в VPN; HTTPS-проба не начата.")
        return {"before": before, "effective": effective, "actions": self.actions,
                "lease_seconds": LEASE_SECONDS}

    def rollback(self):
        if not self.armed:
            return {"ok": True, "note": "Изменения не начинались."}
        spec = self.spec
        rows = self.ops.rows(spec["target"])
        own = owned_rows(rows, spec)
        # A different unscoped static route indicates somebody replaced ours. Do not
        # delete it, even though this means a human should review the resulting state.
        foreign = [row for row in rows if "S" in row["flags"] and "I" not in row["flags"]
                   and row not in own]
        if foreign:
            return {"ok": False, "note": "Маршрут изменён другим компонентом; чужая запись не удалялась.",
                    "rows": rows}
        if own:
            argv = ["/sbin/route", "-n", "delete", "-host", spec["target"], spec["gateway"]]
            self.actions.append({"argv": argv, "output": self.ops.run(argv)})
        if owned_rows(self.ops.rows(spec["target"]), spec):
            return {"ok": False, "note": "Временный маршрут всё ещё присутствует."}
        self.journal({"status": "inactive"})
        self.armed = False
        try:
            effective = self.ops.route(spec["target"])
        except ProbeError:
            effective = {"note": "Маршрут не найден после удаления; возможно, сеть/VPN отключены."}
        return {"ok": True, "effective": effective, "actions": self.actions,
                "note": "Временная статическая запись отсутствует; кешированный маршрут может создаваться заново."}


def emit(value):
    try:
        print(json.dumps(value, ensure_ascii=False), flush=True)
    except (BrokenPipeError, OSError):
        pass


def wait_for_release(fd, deadline, clock=time.monotonic, poll=select.select, reader=os.read):
    while clock() < deadline:
        if poll([fd], [], [], min(0.5, max(0, deadline - clock())))[0]:
            data = reader(fd, 4096)
            return "parent_eof" if not data else "release"
    return "deadline"


def health_check():
    """Exercise the real pipe/deadline with root, without any system operations."""
    def interrupted(signum, frame):
        raise ProbeError("Проверка связи прервана сигналом {}.".format(signum))
    for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        emit({"event": "ready", "mode": "health", "uid": os.geteuid(),
              "remaining_seconds": HEALTH_SECONDS, "network_changes": False})
        reason = wait_for_release(sys.stdin.fileno(), time.monotonic() + HEALTH_SECONDS)
        emit({"event": "health_complete", "ok": True, "reason": reason, "network_changes": False})
        return 0
    except (ProbeError, OSError) as exc:
        emit({"event": "health_complete", "ok": False, "message": str(exc), "network_changes": False})
        return 1


def write_journal(fd, value):
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, json.dumps(value).encode("utf-8"))
    os.fsync(fd)


def acquire_journal():
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        os.close(fd)
        raise ProbeError("Небезопасные права журнала отката.")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise ProbeError("Другой маршрутный помощник ещё работает; сначала завершите его сеанс.")
    try:
        # A full split session journals up to 131 IPv4 routes, not just one host.
        contents = os.read(fd, 131073)
        if len(contents) > 131072:
            raise ValueError("oversized journal")
        previous = json_codec.loads(contents) if contents else {"status": "inactive"}
    except ValueError:
        os.close(fd)
        raise ProbeError("Журнал отката повреждён; автоматическая новая проба запрещена.")
    return fd, previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("lease", "recover", "health"))
    for key in ("target", "gateway", "source", "interface", "vpn-interface"):
        parser.add_argument("--" + key)
    args = parser.parse_args()
    if os.geteuid() != 0:
        emit({"event": "error", "message": "Помощнику нужны права администратора через sudo."})
        return 2
    # This acknowledgement is emitted before opening a journal or touching routes.
    emit({"event": "hello", "protocol": PROTOCOL_VERSION, "mode": args.mode,
          "uid": os.geteuid(), "pid": os.getpid(), "session_id": os.getsid(0)})
    if args.mode == "health":
        return health_check()
    fd = None
    lease = None
    outcome = 0
    try:
        fd, previous = acquire_journal()
        journal = lambda value: write_journal(fd, value)
        if args.mode == "recover":
            if previous.get("status") != "armed":
                emit({"event": "rolled_back", "rollback": {"ok": True, "note": "Активного журнала пробы нет."}})
                return 0
            if previous.get("kind") == "ipv4-split-v1":
                raise ProbeError("Это журнал разделения трафика; запустите «Выключить разделение.command».")
            if previous.get("owner") != int(os.environ.get("SUDO_UID", os.getuid())):
                raise ProbeError("Восстановление должен запускать тот же пользователь, что выполнял пробу.")
            lease = RouteLease(previous["spec"], journal=journal)
            lease.armed = True
        else:
            if previous.get("status") == "armed":
                raise ProbeError("Остался журнал незавершённой пробы. Запустите «Вернуть маршрут.command».")
            spec = {key: getattr(args, key) for key in ("target", "gateway", "source", "interface", "vpn_interface")}
            lease = RouteLease(spec, journal=journal)
            def interrupted(signum, frame):
                raise ProbeError("Получен сигнал {}; выполняется откат.".format(signum))
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, interrupted)
            # Deadline includes mutation setup; it is not extended by parent messages.
            deadline = time.monotonic() + LEASE_SECONDS
            ready = lease.begin()
            ready["remaining_seconds"] = max(0, deadline - time.monotonic())
            emit({"event": "ready", **ready})
            reason = wait_for_release(sys.stdin.fileno(), deadline)
            emit({"event": "lease_end", "reason": reason})
    except (ProbeError, ValueError, TypeError, OSError, KeyError) as exc:
        emit({"event": "error", "message": str(exc)})
        outcome = 1
    finally:
        if lease:
            # A second Ctrl+C must not interrupt the rollback already in progress.
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, signal.SIG_IGN)
            try:
                restored = lease.rollback()
                emit({"event": "rolled_back", "rollback": restored})
                if not restored["ok"]:
                    outcome = 3
            except Exception as exc:
                emit({"event": "rollback_error", "message": str(exc)})
                outcome = 3
        if fd is not None:
            os.close(fd)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
