#!/usr/bin/python3
"""Read-only, offline-capable FortiClient diagnostics for this Mac (Python 3.9+)."""

import argparse
import concurrent.futures
import datetime as dt
import difflib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "diagnostics"
PUBLIC_HOSTS = ("example.com", "www.apple.com")
TZ = ZoneInfo("Asia/Bangkok")
SCHEMA = 1
MAX_TARGETS = 12
RELATED = re.compile(r"forti|trueconf|windows app|microsoft remote desktop|tailscale", re.I)
UUID = r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"


def now():
    return dt.datetime.now(TZ).isoformat(timespec="seconds")


def clean_output(value):
    """Omit proxy URLs, credential-looking properties and terminal control codes."""
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = "".join(c for c in value if c in "\n\t" or ord(c) >= 32)
    lines = []
    for line in value.splitlines():
        if re.search(r"ProxyAutoConfigURL|password|passwd|cookie|secret|token|authorization", line, re.I):
            line = "[поле с URL прокси или возможными учётными данными опущено]"
        if re.match(r"\s*ether\s", line):
            line = "\tether [MAC-адрес опущен]"
        lines.append(line)
    return "\n".join(lines)


def command(name, argv, timeout=10):
    started = time.monotonic()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, env=env, text=True, errors="replace")
        code, output, timed_out = result.returncode, result.stdout, False
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        code, timed_out = None, True
    except OSError as exc:
        code, output, timed_out = None, str(exc), False
    return {"name": name, "argv": argv, "exit_code": code,
            "timeout": timed_out, "seconds": round(time.monotonic() - started, 2),
            "output": clean_output(output)}


def batch(jobs):
    # Every subprocess is bounded. DNS/HTTPS failures must not stop local collection.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(lambda job: command(*job), jobs))


def valid_host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if (len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value)
            or any(not label or len(label) > 63 for label in value.rstrip(".").split("."))):
        raise ValueError("нужно имя сервера или IP, без URL, логина и пароля")
    return value


def load_targets(file_path):
    if not file_path.exists():
        return []
    targets = []
    for number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), 1):
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        if len(parts) != 3:
            raise ValueError("{}:{}: формат: метка сервер порт".format(file_path, number))
        label, host, port = parts
        if not re.fullmatch(r"[\w.-]{1,40}", label):
            raise ValueError("{}:{}: некорректная метка".format(file_path, number))
        host = valid_host(host)
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError("{}:{}: порт должен быть от 1 до 65535".format(file_path, number))
        targets.append({"label": label, "host": host, "port": int(port)})
        if len(targets) > MAX_TARGETS:
            raise ValueError("допускается не более {} рабочих серверов".format(MAX_TARGETS))
    return targets


def related_processes(raw):
    processes = []
    for line in raw.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
            processes.append((int(fields[0]), int(fields[1]), fields[2]))
    selected = {pid for pid, _, executable in processes if RELATED.search(executable)}
    while True:
        children = {pid for pid, parent, _ in processes if parent in selected}
        if children <= selected:
            break
        selected |= children
    return [(pid, parent, executable) for pid, parent, executable in processes if pid in selected]


def peer_addresses(raw):
    peers = set()
    for line in raw.splitlines():
        if not line.startswith("n") or "->" not in line:
            continue
        endpoint = line.split("->", 1)[1].split(" ", 1)[0]
        host = endpoint.rsplit(":", 1)[0].strip("[]")
        try:
            address = ipaddress.ip_address(host)
            if not address.is_loopback and not address.is_unspecified:
                peers.add(str(address))
        except ValueError:
            continue
    return sorted(peers)


def resolved_addresses(raw):
    addresses = set()
    for line in raw.splitlines():
        match = re.match(r"\s*(?:ip_address|ipv6_address):\s*(\S+)", line)
        if match:
            try:
                addresses.add(str(ipaddress.ip_address(match.group(1))))
            except ValueError:
                pass
    return sorted(addresses)


def dns_server_addresses(raw):
    addresses = set()
    for value in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", raw):
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return sorted(addresses)


def route_job(address):
    address = str(ipaddress.ip_address(address))
    family = ["-inet6"] if ":" in address else []
    return ("route " + address, ["/sbin/route", "-n", "get"] + family + [address], 6)


def snapshot(label):
    jobs = [
        ("VPN services", ["/usr/sbin/scutil", "--nc", "list"], 10),
        ("Network state", ["/usr/sbin/scutil", "--nwi"], 10),
        ("DNS", ["/usr/sbin/scutil", "--dns"], 10),
        ("System proxies (URLs omitted)", ["/usr/sbin/scutil", "--proxy"], 10),
        ("Interfaces", ["/sbin/ifconfig", "-a"], 10),
        ("IPv4 routes", ["/usr/sbin/netstat", "-rn", "-f", "inet"], 10),
        ("IPv6 routes", ["/usr/sbin/netstat", "-rn", "-f", "inet6"], 10),
        ("IPv4 default", ["/sbin/route", "-n", "get", "default"], 6),
        ("IPv6 default", ["/sbin/route", "-n", "get", "-inet6", "default"], 6),
        ("Network extensions", ["/usr/bin/systemextensionsctl", "list"], 10),
    ]
    state = {"label": label, "at": now(), "results": batch(jobs)}
    dns = next(item["output"] for item in state["results"] if item["name"] == "DNS")
    state["results"].extend(batch([route_job(address) for address in dns_server_addresses(dns)[:16]]))
    services = next(item["output"] for item in state["results"] if item["name"] == "VPN services")
    for line in services.splitlines():
        if "com.fortinet" in line.lower():
            match = re.search(UUID, line)
            if match:
                state["results"].append(command("FortiClient connection status",
                    ["/usr/sbin/scutil", "--nc", "status", match.group(0)], 6))
    return state


def app_connections(label):
    result = command("Related application processes (no arguments)",
                     ["/bin/ps", "-axo", "pid=,ppid=,comm="], 6)
    processes = related_processes(result["output"])
    # Unrelated process names are never stored in the report.
    result["output"] = "\n".join("{} {} {}".format(*row) for row in processes)
    results = [result]
    if processes:
        pids = ",".join(str(row[0]) for row in processes[:100])
        sockets = command("Related application sockets", ["/usr/sbin/lsof", "-nP", "-a",
                          "-p", pids, "-i", "-Fpcn"], 10)
        results.append(sockets)
        peers = peer_addresses(sockets["output"])
        results.extend(batch([route_job(address) for address in peers[:32]]))
    else:
        peers = []
    return {"label": label, "at": now(), "results": results, "observed_peers": peers,
            "note": "Адреса наблюдаемых соединений не являются готовым списком рабочих маршрутов. "
                    "Сокеты системных/чужих процессов могут быть недоступны без прав администратора."}


def curl_job(host, family, pinned=None):
    argv = ["/usr/bin/curl", "-q", "--noproxy", "*", "--head", "--silent", "--show-error",
            "--connect-timeout", "4", "--max-time", "8", "--output", "/dev/null",
            "--write-out", "http_code=%{http_code}\nremote_ip=%{remote_ip}\n"
            "dns_seconds=%{time_namelookup}\nconnect_seconds=%{time_connect}\n"
            "tls_seconds=%{time_appconnect}\ntotal_seconds=%{time_total}\n"
            "tls_verify=%{ssl_verify_result}\n", "-" + family]
    suffix = "system DNS"
    if pinned:
        address = ipaddress.ip_address(pinned)
        if address.version != int(family):
            raise ValueError("семейство IP не совпало")
        text = "[{}]".format(address) if address.version == 6 else str(address)
        argv += ["--resolve", "{}:443:{}".format(host, text)]
        suffix = "baseline IP (no DNS)"
    argv.append("https://" + host + "/")
    return ("HTTPS {} IPv{} {}".format(host, family, suffix), argv, 11)


def verified_pins(results):
    pins = {}
    for host in PUBLIC_HOSTS:
        for family in ("4", "6"):
            name = "HTTPS {} IPv{} system DNS".format(host, family)
            probe = next((item for item in results if item["name"] == name), None)
            if not probe or probe["exit_code"] != 0 or probe["timeout"]:
                continue
            fields = dict(re.findall(r"^(\w+)=(\S*)$", probe["output"], re.M))
            try:
                address = ipaddress.ip_address(fields.get("remote_ip", ""))
                # Some stacks expose an IPv4 connection as ::ffff:a.b.c.d even for -6.
                # Such a result must not seed a supposedly native IPv6 test.
                if address.version == 6 and address.ipv4_mapped is not None:
                    continue
                if (address.version == int(family) and fields.get("tls_verify") == "0"
                        and int(fields.get("http_code", "0")) > 0):
                    pins.setdefault(host, {})[family] = str(address)
            except ValueError:
                continue
    return pins


def public_checks(baseline=None):
    jobs = []
    pins = baseline.get("public_pins", {}) if baseline else {}
    for host in PUBLIC_HOSTS:
        jobs.append(("System resolution " + host,
                     ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host], 8))
        for family in ("4", "6"):
            jobs.append(curl_job(host, family))
            pinned = pins.get(host, {}).get(family)
            if pinned:
                jobs.append(curl_job(host, family, pinned))
                jobs.append(route_job(pinned))
    results = batch(jobs)
    return {"label": "Public DNS and HTTPS", "at": now(), "results": results,
            "verified_pins": verified_pins(results),
            "note": "Проверки curl используют прямые соединения, игнорируют прокси и .curlrc, "
                    "сохраняют проверку TLS. HTTP 3xx/4xx при успешном curl тоже подтверждает "
                    "ответ сервера. IPv6 может отсутствовать. Закреплённые IP взяты только "
                    "из успешного HTTPS до VPN; при отсутствии такого снимка тест без DNS пропущен. "
                    "IPv4-mapped адрес ::ffff:... не подтверждает нативный IPv6 и не закрепляется как IPv6. "
                    "Смена/недоступность IP сервера между снимками тоже может влиять на результат."}


def target_checks(targets):
    jobs = []
    addresses = set()
    for target in targets:
        host, port = target["host"], target["port"]
        jobs.append(("Target resolution " + target["label"],
                     ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host], 8))
        jobs.append(("Target TCP " + target["label"],
                     ["/usr/bin/nc", "-n" if is_ip(host) else "-v", "-z", "-G", "3",
                      "-w", "3", host, str(port)], 8))
        if is_ip(host):
            addresses.add(host)
    results = batch(jobs)
    for result in results:
        if result["name"].startswith("Target resolution "):
            addresses.update(resolved_addresses(result["output"]))
    results.extend(batch([route_job(address) for address in sorted(addresses)[:48]]))
    return {"label": "Optional work servers", "at": now(), "results": results,
            "note": "TCP-проверка открывает соединение с указанным портом без входа и отправки "
                    "данных приложения. Она не заменяет RDP-сеанс или звонок TrueConf. "
                    "Проверяются только явно указанные серверы; диапазоны не сканируются."}


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def find_baseline(output_root):
    for folder in sorted(output_root.glob("baseline-*"), reverse=True):
        try:
            data = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            if (data.get("schema") == SCHEMA and data.get("mode") == "baseline"
                    and data.get("status") == "complete"):
                return data, folder
        except (OSError, ValueError):
            continue
    return None, None


def result_map(stage):
    return {item["name"]: item for item in stage.get("results", [])}


def render_stage(stage):
    lines = ["", "=== {} | {} ===".format(stage["label"], stage["at"])]
    if stage.get("note"):
        lines.append(stage["note"])
    for item in stage.get("results", []):
        lines.extend(["", "--- {} ---".format(item["name"]),
                      "$ " + shlex.join(item["argv"]),
                      "exit={} timeout={} seconds={}".format(
                          item["exit_code"], item["timeout"], item["seconds"]),
                      item["output"] or "[нет вывода]"])
    return lines


def render_report(data):
    lines = ["FORTICLIENT: АВТОНОМНАЯ ДИАГНОСТИКА", "Начало: " + data["started_at"],
             "Режим: " + data["mode"], "Статус: " + data["status"],
             "Сетевые настройки сборщиком не изменялись.",
             "Отчёт содержит внутренние IP, имена доменов/серверов и сетевую структуру.",
             "Сборщик не читает Keychain и профили/логи FortiClient; не сохраняет окружение и аргументы процессов.",
             "Ошибки и таймауты команд записаны явно; отсутствие ответа не доказывает блокировку."]
    lines.extend("ПРИМЕЧАНИЕ: " + text for text in data.get("notes", []))
    baseline = data.get("baseline")
    if baseline:
        lines.extend(["", "Исходный снимок: " + data["baseline_path"],
                      "Дата исходного снимка: " + baseline["started_at"]])
        for stage in baseline["stages"]:
            lines.extend(render_stage(stage))
    for stage in data["stages"]:
        lines.extend(render_stage(stage))
    if baseline and baseline["stages"] and data["stages"]:
        before, after = result_map(baseline["stages"][0]), result_map(data["stages"][0])
        lines.extend(["", "=== ИЗМЕНЕНИЯ ДО / ПОСЛЕ (интерпретация требует анализа) ==="])
        for name in ("VPN services", "Network state", "DNS", "System proxies (URLs omitted)",
                     "IPv4 routes", "IPv6 routes", "IPv4 default", "IPv6 default"):
            old, new = before.get(name), after.get(name)
            if not old or not new:
                continue
            lines.extend(["", "--- " + name + " ---"])
            diff = list(difflib.unified_diff(old["output"].splitlines(), new["output"].splitlines(),
                                           fromfile="before", tofile="after", lineterm=""))
            lines.extend(diff or ["[вывод совпадает; коды завершения указаны выше]"])
    return "\n".join(lines) + "\n"


def save_report(folder, data):
    for filename, contents in (("report.json", json.dumps(data, ensure_ascii=False, indent=2) + "\n"),
                               ("report.txt", render_report(data))):
        temporary = folder / (filename + ".tmp")
        temporary.write_text(contents, encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(str(temporary), str(folder / filename))


def add_stage(folder, data, stage):
    data["stages"].append(stage)
    save_report(folder, data)


def collect(mode, output_root, targets):
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = dt.datetime.now(TZ).strftime("%Y%m%d-%H%M%S-%f")
    folder = output_root / (mode + "-" + stamp)
    folder.mkdir(mode=0o700)
    data = {"schema": SCHEMA, "mode": mode, "started_at": now(), "status": "collecting",
            "notes": [], "stages": [], "targets": targets}
    if mode == "connected":
        baseline, baseline_folder = find_baseline(output_root)
        if baseline:
            data.update(baseline=baseline, baseline_path=str(baseline_folder / "report.txt"))
            age = dt.datetime.now(TZ) - dt.datetime.fromisoformat(baseline["started_at"])
            if age.total_seconds() > 24 * 3600:
                data["notes"].append("Исходному снимку больше суток. Он может относиться к другой сети; "
                                     "возраст учитывать при сравнении, закреплённые IP могли измениться.")
        else:
            data["notes"].append("Исходный снимок не найден: сравнение до/после и HTTPS по исходному IP "
                                 "недоступны. Остальная диагностика будет собрана.")
    save_report(folder, data)
    print("Файл отчёта: {}".format(folder / "report.txt"), flush=True)
    try:
        print("1/4: маршруты, DNS, интерфейсы и VPN...", flush=True)
        state = snapshot("BEFORE VPN" if mode == "baseline" else "VPN: initial state")
        add_stage(folder, data, state)
        statuses = [item["output"].strip().lower() for item in state["results"]
                    if item["name"] == "FortiClient connection status"]
        if mode == "baseline" and any(text.startswith("connected") or text.startswith("connecting")
                                      for text in statuses):
            data["status"] = "invalid_baseline_vpn_active"
            data["notes"].append("FortiClient уже подключён/подключается. Этот снимок не используется как исходный.")
            save_report(folder, data)
            return folder, 2
        if mode == "connected" and not any(text.startswith("connected") for text in statuses):
            data["notes"].append("scutil не подтвердил Connected для FortiClient. Это может быть ограничением "
                                 "видимости статуса; факт подключения сверить с приложением и маршрутами.")
        print("2/4: соединения рабочих приложений...", flush=True)
        add_stage(folder, data, app_connections("Application connections: initial"))
        print("3/4: проверки DNS/HTTPS (ошибки при VPN ожидаемы, таймауты ограничены)...", flush=True)
        public = public_checks(data.get("baseline"))
        add_stage(folder, data, public)
        if mode == "baseline":
            data["public_pins"] = public["verified_pins"]
            addresses = {address for families in data["public_pins"].values() for address in families.values()}
            add_stage(folder, data, {"label": "Routes to verified public IPs", "at": now(),
                                    "results": batch([route_job(address) for address in sorted(addresses)])})
        if targets:
            add_stage(folder, data, target_checks(targets))
        print("4/4: повторный снимок соединений и состояния сети...", flush=True)
        if mode == "connected":
            add_stage(folder, data, app_connections("Application connections: final"))
            add_stage(folder, data, snapshot("VPN: final state"))
        metadata = [("macOS version", ["/usr/bin/sw_vers"], 5),
                    ("Architecture", ["/usr/bin/uname", "-m"], 5)]
        for app in ("FortiClient", "Windows App", "TrueConf Client"):
            metadata.append((app + " version", ["/usr/bin/plutil", "-extract",
                             "CFBundleShortVersionString", "raw", "-o", "-",
                             "/Applications/" + app + ".app/Contents/Info.plist"], 5))
        add_stage(folder, data, {"label": "System and application versions", "at": now(),
                                "results": batch(metadata)})
        data["status"] = "complete"
        data["finished_at"] = now()
        save_report(folder, data)
        return folder, 0
    except KeyboardInterrupt:
        data["status"] = "interrupted"
        data["notes"].append("Сбор прерван пользователем; завершённые этапы сохранены.")
        save_report(folder, data)
        return folder, 130
    except Exception as exc:
        data["status"] = "error"
        data["notes"].append("Ошибка сборщика: {}: {}".format(type(exc).__name__, clean_output(str(exc))))
        save_report(folder, data)
        print(data["notes"][-1], file=sys.stderr)
        return folder, 1


def main():
    parser = argparse.ArgumentParser(description="Автономная диагностика FortiClient без изменения сети.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--baseline", action="store_true", help="исходный снимок ДО подключения FortiClient")
    modes.add_argument("--connected", action="store_true", help="снимок ПОСЛЕ подключения (по умолчанию)")
    parser.add_argument("--interactive", action="store_true", help="дождаться Enter перед сбором")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="каталог отчётов")
    parser.add_argument("--targets", type=Path, default=ROOT / "work-targets.txt", help="необязательный список серверов")
    args = parser.parse_args()
    os.umask(0o077)
    mode = "baseline" if args.baseline else "connected"
    try:
        targets = load_targets(args.targets)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("FortiClient: автономный сбор диагностики. Интернет для работы сборщика не нужен.")
    print("Сетевые настройки не меняются. Отчёт сохранится локально, без отправки в интернет.")
    if args.interactive:
        if mode == "connected":
            baseline, folder = find_baseline(args.output)
            print("Исходный снимок: " + (baseline["started_at"] if baseline else "не найден"))
            print("Дождитесь подключения FortiClient НА MAC. Откройте Windows App и TrueConf на Mac,")
            print("попробуйте подключиться к рабочему столу и серверу TrueConf и оставьте приложения открытыми.")
        else:
            print("FortiClient и другие VPN должны быть отключены.")
        try:
            input("Когда будете готовы, нажмите Enter (Ctrl+C — отмена): ")
        except (KeyboardInterrupt, EOFError):
            return 130
    folder, code = collect(mode, args.output.resolve(), targets)
    print("\nГотово. Статус завершения: {}.\nОтчёт: {}".format(code, folder / "report.txt"))
    if mode == "connected":
        print("Теперь можно отключить FortiClient, дождаться восстановления интернета")
        print("и написать в чате: «Прочитай последнюю диагностику». Файл уже сохранён.")
    return code


if __name__ == "__main__":
    sys.exit(main())
