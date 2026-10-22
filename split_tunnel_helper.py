#!/usr/bin/python3
"""Root guardian: additive IPv4 split routes, bounded session, exact rollback."""

import argparse
import copy
import ipaddress
import json
import os
import re
import select
import signal
import socket
import sys
import time
import json_codec

import route_probe_helper as base


PREFIXES = ("0.0.0.0/1", "128.0.0.0/1")
KIND = "ipv4-split-v1"
PROTOCOL = base.PROTOCOL_VERSION


def network(value):
    if value == "default":
        return "0.0.0.0/0"
    address, sep, bits = value.partition("/")
    parts = address.split(".")
    if not 1 <= len(parts) <= 4 or not all(p.isdecimal() for p in parts):
        raise ValueError("not IPv4")
    padded = ".".join(parts + ["0"] * (4 - len(parts)))
    return str(ipaddress.IPv4Network(padded + "/" + (bits if sep else str(8 * len(parts))), strict=False))


def table(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            prefix = network(fields[0])
        except ValueError:
            continue
        rows.append({"prefix": prefix, "gateway": fields[1], "flags": fields[2], "interface": fields[3]})
    return rows


class Operations(base.Operations):
    def table(self):
        return table(self.run(["/usr/sbin/netstat", "-rn", "-f", "inet"]))

    def dns(self):
        return self.run(["/usr/sbin/scutil", "--dns"])

    def index(self, interface):
        return socket.if_nametoindex(interface)

    def interface_gateways(self, interface):
        # netstat can display a named AF_LINK gateway as `utunN`, `link#N`,
        # or a point-to-point local IPv4. Freeze these narrowly
        # sourced representations BEFORE writing the route; never accept an
        # arbitrary gateway just because its interface happens to match.
        raw = self.run(["/sbin/ifconfig", interface])
        addresses = re.findall(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\b", raw, re.M)
        return sorted({interface, "link#" + str(self.index(interface))}
                      | {str(ipaddress.IPv4Address(value)) for value in addresses})


def validate(spec):
    if spec.get("kind") != KIND:
        raise base.ProbeError("Неизвестный формат сеанса разделения.")
    for key in ("source", "gateway", "server"):
        ipaddress.IPv4Address(spec[key])
    if not re.fullmatch(r"en\d+", spec["interface"]) or not re.fullmatch(r"utun\d+", spec["vpn_interface"]):
        raise base.ProbeError("Некорректные интерфейсы.")
    if type(spec["seconds"]) is not int or (spec["seconds"] != 0 and not 60 <= spec["seconds"] <= 8 * 3600):
        raise base.ProbeError("Длительность: 0 (без лимита) или от минуты до 8 часов.")
    work = spec["work_addresses"]
    if not isinstance(work, list) or not 1 <= len(work) <= 128 or len(set(work)) != len(work):
        raise base.ProbeError("Нужен непустой список не более 128 уникальных рабочих IPv4.")
    for value in work:
        address = ipaddress.IPv4Address(value)
        if (address.is_loopback or address.is_multicast or address.is_link_local or address.is_unspecified
                or address.is_reserved or value in (spec["gateway"], spec["source"], spec["server"])):
            raise base.ProbeError("Недопустимый рабочий адрес: " + value)


def same(row, entry):
    gateways = entry.get("pending_gateways", [entry["gateway"]])
    return (row["prefix"] == entry["prefix"] and row["gateway"] in gateways
            and row["interface"] == entry["interface"] and "S" in row["flags"]
            and "I" not in row["flags"] and ("G" in row["flags"]) == (entry["via"] == "gateway")
            and not any(flag in row["flags"] for flag in ("R", "B", "L", "W")))


def route_command(verb, entry):
    prefix = ipaddress.IPv4Network(entry["prefix"])
    argv = ["/sbin/route", "-n", verb, "-host" if prefix.prefixlen == 32 else "-net"]
    target = str(prefix.network_address) if prefix.prefixlen == 32 else str(prefix)
    if entry["via"] == "interface":
        return argv + [target, "-interface", entry["interface"]]
    return argv + [target, entry["gateway"]]


class SplitLease:
    def __init__(self, spec, ops=None, journal=None, observer=None):
        validate(spec)
        self.spec = spec
        self.ops = ops or Operations()
        self.journal = journal or (lambda value: None)
        self.observer = observer or (lambda value: None)
        self.entries = []
        self.actions = []
        self.observations = []
        self.expected = {}
        self.armed = False
        self.dns_before = None

    def save(self):
        self.journal({"status": "armed", "kind": KIND, "spec": self.spec,
                      "owner": int(os.environ.get("SUDO_UID", os.getuid())), "entries": copy.deepcopy(self.entries)})

    def context(self):
        spec = self.spec
        vpn = self.ops.forti()
        if vpn != {"interface": spec["vpn_interface"], "server": spec["server"]}:
            raise base.ProbeError("VPN отключён или переподключён; сеанс завершается.")
        self.ops.physical(spec["interface"], spec["gateway"], spec["source"])

    def plan(self):
        self.context()
        spec = self.spec
        rows = self.ops.table()
        if any(row["prefix"] in PREFIXES for row in rows):
            raise base.ProbeError("Маршруты /1 уже заняты; чужие записи не меняются.")
        self.dns_before = self.ops.dns()
        dns = set()
        for value in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", self.dns_before):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == 4:
                dns.add(str(address))
        work = set(spec["work_addresses"])
        for address in dns:
            if self.ops.route(address).get("interface") == spec["vpn_interface"]:
                work.add(str(ipaddress.IPv4Address(address)))
        if len(work) > 128:
            raise base.ProbeError("Слишком много рабочих/DNS адресов.")
        self.expected = {}
        planned = []
        interface_gateways = self.ops.interface_gateways(spec["vpn_interface"])
        for address in sorted(work):
            before = self.ops.route(address)
            if before.get("interface") != spec["vpn_interface"]:
                raise base.ProbeError("Рабочий адрес {} сейчас не в Forti VPN; разрешите пересечение вручную.".format(address))
            self.expected[address] = {"interface": spec["vpn_interface"]}
            exact = [r for r in rows if r["prefix"] == address + "/32" and "I" not in r["flags"]]
            if any("W" not in r["flags"] or "S" in r["flags"] for r in exact):
                continue  # Preserve existing explicit/connected VPN host routes.
            planned.append({"prefix": address + "/32", "gateway": spec["vpn_interface"],
                            "interface": spec["vpn_interface"], "via": "interface",
                            "pending_gateways": interface_gateways})
        # Keep the VPN transport outside the tunnel even after adding broad routes.
        transport = self.ops.route(spec["server"])
        if transport.get("interface") != spec["interface"] or transport.get("destination") != spec["server"]:
            exact = [r for r in rows if r["prefix"] == spec["server"] + "/32"
                     and ("S" in r["flags"] or "W" not in r["flags"])]
            if exact:
                raise base.ProbeError("Конфликт отдельного маршрута VPN-сервера.")
            planned.append({"prefix": spec["server"] + "/32", "gateway": spec["gateway"],
                            "interface": spec["interface"], "via": "gateway"})
        for prefix in PREFIXES:
            planned.append({"prefix": prefix, "gateway": spec["gateway"],
                            "interface": spec["interface"], "via": "gateway"})
        clones = [r for r in rows if r["interface"] == spec["vpn_interface"] and "H" in r["flags"]
                  and "W" in r["flags"] and "S" not in r["flags"]
                  and ipaddress.IPv4Network(r["prefix"]).network_address.is_multicast is False]
        if len(clones) > 512:
            raise base.ProbeError("Слишком много кешированных маршрутов; автоматическое применение остановлено.")
        return {"add": planned, "discard_vpn_host_clones": clones,
                "protected_addresses": sorted(work), "dns_policy": "unchanged_corporate_via_vpn",
                "ipv6_policy": "unchanged_not_split", "seconds": spec["seconds"]}

    def act(self, argv):
        action = {"argv": argv}
        self.actions.append(action)
        try:
            action["output"] = self.ops.run(argv)
        except Exception as exc:
            action["error"] = str(exc)
            raise

    def observe(self, entry, phase, rows=None, effective=False):
        rows = self.ops.table() if rows is None else rows
        snapshot = {"event": "route_observation", "phase": phase, "entry": copy.deepcopy(entry),
                    "rows": [r for r in rows if r["prefix"] == entry["prefix"]]}
        if effective:
            try:
                snapshot["effective"] = self.ops.route(str(ipaddress.IPv4Network(entry["prefix"]).network_address))
            except Exception as exc:
                snapshot["effective_error"] = str(exc)
        self.observations.append(snapshot)
        self.observer(snapshot)
        return snapshot["rows"]

    def begin(self):
        plan = self.plan()
        self.armed = True
        self.save()
        # Discard only disposable clones of the VPN's routes, never static routes.
        # Otherwise cached public /32 entries could out-prioritize the new /1s.
        for row in plan["discard_vpn_host_clones"]:
            current = self.ops.table()
            if row not in current:
                continue
            argv = ["/sbin/route", "-n", "delete", "-host"]
            if "I" in row["flags"]:
                argv += ["-ifscope", row["interface"]]
            self.act(argv + [str(ipaddress.IPv4Network(row["prefix"]).network_address)])
        for entry in plan["add"]:
            # Never adopt or overwrite a route that appeared after preflight.
            if any(r["prefix"] == entry["prefix"] and "I" not in r["flags"]
                   and ("S" in r["flags"] or "W" not in r["flags"]) for r in self.ops.table()):
                raise base.ProbeError("Таблица изменилась во время применения; выполняется откат.")
            entry = copy.deepcopy(entry)
            self.entries.append(entry)
            self.save()  # Write-ahead: even a timeout after successful add is recoverable.
            try:
                self.act(route_command("add", entry))
            finally:
                observed = self.observe(entry, "after_add", effective=True)
            matches = [r for r in observed if same(r, entry)]
            if len(matches) != 1:
                raise base.ProbeError("Добавление маршрута не подтверждено: " + entry["prefix"])
            # After initial confirmation, rollback/monitoring use the exact
            # observed gateway. Another local address is NOT a valid replacement.
            entry["gateway"] = matches[0]["gateway"]
            entry.pop("pending_gateways", None)
            self.save()
        self.check()
        return plan

    def check(self):
        self.context()
        rows = self.ops.table()
        for entry in self.entries:
            if not any(same(row, entry) for row in rows):
                raise base.ProbeError("Маршрут исчез или изменён; повторное навязывание настроек не выполняется.")
        for address in self.expected:
            if self.ops.route(address).get("interface") != self.spec["vpn_interface"]:
                raise base.ProbeError("Рабочий адрес вышел из VPN: " + address)
        for address in ("1.1.1.1", "8.8.8.8", self.spec["server"]):
            route = self.ops.route(address)
            if route.get("interface") != self.spec["interface"]:
                raise base.ProbeError("Прямой путь не подтверждён: " + address)
        if self.ops.dns() != self.dns_before:
            raise base.ProbeError("DNS изменился в ходе сеанса; безопасный откат.")

    def rollback(self):
        if not self.armed:
            return {"ok": True, "notes": ["Изменений не было."]}
        problems = []
        # Reverse order: restore VPN default precedence before removing work pins.
        for entry in list(reversed(self.entries)):
            try:
                rows = [r for r in self.ops.table() if r["prefix"] == entry["prefix"] and "I" not in r["flags"]]
                self.observe(entry, "before_rollback", rows=rows)
                own = [r for r in rows if same(r, entry)]
                foreign = [r for r in rows if not same(r, entry) and ("S" in r["flags"] or "W" not in r["flags"])]
                if foreign:
                    raise base.ProbeError("Чужая/заменённая запись сохранена: " + entry["prefix"])
                if own:
                    self.act(route_command("delete", entry))
                if any(same(r, entry) for r in self.ops.table()):
                    raise base.ProbeError("Запись осталась: " + entry["prefix"])
                self.observe(entry, "after_rollback")
                self.entries.remove(entry)
                self.save()
            except Exception as exc:
                problems.append(str(exc))
                # Do not remove work exceptions while an internet /1 is still active.
                if entry["prefix"] in PREFIXES:
                    break
        ok = not problems and not self.entries
        if ok:
            self.armed = False
            self.journal({"status": "inactive"})
        return {"ok": ok, "notes": problems, "remaining": list(self.entries), "actions": self.actions,
                "observations": self.observations}


def guard(fd, deadline, lease, clock=time.monotonic, poll=select.select, reader=os.read, wall=time.time):
    checked = clock()
    last_wall = wall()
    while deadline is None or clock() < deadline:
        if poll([fd], [], [], 1 if deadline is None else min(1, max(0, deadline - clock())))[0]:
            data = reader(fd, 4096)
            return "release" if data else "parent_eof"
        current_wall = wall()
        if current_wall - last_wall > 15 or current_wall < last_wall - 1:
            raise base.ProbeError("Сон/длительная пауза или изменение времени; сеанс завершается.")
        last_wall = current_wall
        if clock() - checked >= 5:
            lease.check()
            checked = clock()
    return "deadline"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("lease", "recover", "health"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        base.emit({"event": "error", "message": "Нужны права администратора через sudo."})
        return 2
    base.emit({"event": "hello", "protocol": PROTOCOL, "mode": args.mode, "uid": os.geteuid()})
    if args.mode == "health":
        return base.health_check()  # No journal and no route/DNS/system operations.
    fd, lease, code = None, None, 0
    try:
        fd, previous = base.acquire_journal()
        journal = lambda value: base.write_journal(fd, value)
        if args.mode == "recover":
            if previous.get("status") != "armed":
                base.emit({"event": "rolled_back", "rollback": {"ok": True, "notes": ["Активного журнала нет."]}})
                return 0
            if previous.get("kind") != KIND:
                raise base.ProbeError("Это журнал одиночной пробы; используйте «Вернуть маршрут.command».")
            if previous.get("owner") != int(os.environ.get("SUDO_UID", os.getuid())):
                raise base.ProbeError("Восстановление должен запускать владелец сеанса.")
            lease = SplitLease(previous["spec"], journal=journal, observer=base.emit)
            lease.entries = previous["entries"]
            lease.armed = True
        else:
            if previous.get("status") == "armed":
                raise base.ProbeError("Остался журнал незавершённых изменений; сначала выполните восстановление.")
            # Bounded newline message; no filenames, commands or DNS settings accepted.
            if not select.select([sys.stdin], [], [], 15)[0]:
                raise base.ProbeError("Не получены параметры сеанса.")
            raw = sys.stdin.buffer.readline(32769)
            if len(raw) > 32768:
                raise base.ProbeError("Слишком большой запрос.")
            spec = json_codec.loads(raw)
            lease = SplitLease(spec, journal=journal, observer=base.emit)
            def interrupted(signum, frame):
                raise base.ProbeError("Сеанс прерван сигналом {}; откат.".format(signum))
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, interrupted)
            deadline = time.monotonic() + spec["seconds"] if spec["seconds"] else None
            plan = lease.begin()
            base.emit({"event": "ready", "plan": plan,
                       "remaining_seconds": max(0, deadline - time.monotonic()) if deadline is not None else None})
            reason = guard(sys.stdin.fileno(), deadline, lease)
            base.emit({"event": "lease_end", "reason": reason})
    except Exception as exc:
        base.emit({"event": "error", "message": str(exc)})
        code = 1
    finally:
        if lease:
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, signal.SIG_IGN)
            try:
                restored = lease.rollback()
                base.emit({"event": "rolled_back", "rollback": restored})
                if not restored["ok"]:
                    code = 3
            except Exception as exc:
                base.emit({"event": "rollback_error", "message": str(exc)})
                code = 3
        if fd is not None:
            os.close(fd)
    return code


if __name__ == "__main__":
    sys.exit(main())
