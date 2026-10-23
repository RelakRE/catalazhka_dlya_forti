#!/usr/bin/python3
"""Offline interactive split-tunnel controller. No route mutation without --apply."""

import argparse
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import route_probe as probe
import route_probe_helper as base
import split_tunnel_helper as helper
import vpn_diagnostics as diag


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "diagnostics"
PREPARED = OUTPUT / "split-prepared.json"
CONTROL_DIR = Path(tempfile.gettempdir()) / ("forti-split-" + str(os.getuid()))
CONTROL = CONTROL_DIR / "control.sock"
CONFIG = ROOT / "split-config.json"
FORTITRAY_LOG = Path.home() / "Library/Application Support/Fortinet/FortiClient/Logs/fortitray.log"


def private_json(path, data):
    import profile_store
    profile_store.save(path, data)


def report(data, folder):
    lines = ["FORTICLIENT: СЕАНС РАЗДЕЛЕНИЯ IPv4", "Начало: " + data["started_at"],
             "Статус: " + data["status"],
             "DNS: без изменений, корпоративные DNS остаются в VPN.",
             "IPv6: без изменений; прямой IPv6 НЕ реализован и НЕ подтверждён.",
             "Отчёт приватный: содержит рабочие адреса, но не пароли и не содержимое соединений."]
    if data.get("kind") == "forti-connection-check":
        lines = ["FORTICLIENT: ДИАГНОСТИКА ВХОДА БЕЗ ИЗМЕНЕНИЯ СЕТИ",
                 "Начало: " + data["started_at"], "Статус: " + data["status"],
                 "Нет sudo, повторной аутентификации, изменений маршрутов, DNS или служб.",
                 "Только разрешённые типы событий, без сырых журналов и введённых значений MFA."]
    for key in ("spec", "plan", "authentication", "acceptance", "rollback", "connection_diagnosis", "notes", "guardian_events"):
        if key in data:
            lines += ["\n" + key + ":", json.dumps(data[key], ensure_ascii=False, indent=2)]
    for stage in data.get("stages", []):
        lines.extend(diag.render_stage(stage))
    private_json(folder / "report.json", data)
    temporary = folder / "report.txt.tmp"
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(str(temporary), str(folder / "report.txt"))


def new_report(mode):
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    folder = OUTPUT / (mode + "-" + dt.datetime.now(diag.TZ).strftime("%Y%m%d-%H%M%S-%f"))
    folder.mkdir(mode=0o700)
    data = {"kind": mode, "started_at": diag.now(), "status": "started", "notes": [], "stages": [], "guardian_events": []}
    report(data, folder)
    print("Отчёт: " + str(folder / "report.txt"), flush=True)
    return folder, data


def login_events(raw, day):
    """Whitelist event types only: never persist raw auth logs, input or URLs."""
    patterns = (
        (r"Request VPN connect$", "connect_requested"),
        (r"Resolved IP address (\d+\.\d+\.\d+\.\d+) for domain name:", "gateway_resolved"),
        (r"HttpsNWConnection\.swift:\d+ Connected to (\d+\.\d+\.\d+\.\d+)$", "gateway_transport_connected"),
        (r"Server requires RSA PIN$", "mfa_requested"),
        (r"Authentication passed$", "authentication_passed"),
        (r"Login successful$", "login_successful"),
        (r"Error from server: Permission denied\.$", "server_permission_denied"),
        (r"Login failed\. Result: (\d+)$", "login_failed"),
        (r"Request VPN disconnect$", "disconnect_requested"),
        (r"VPN tunnel provider Main status changed: Connected$", "tunnel_connected"),
    )
    events = []
    for line in raw.splitlines():
        timestamp = re.match(r"^(\d{8} \d{2}:\d{2}:\d{2}\.\d+) TZ=([+-]\d{4}) ", line)
        if not timestamp or not line.startswith(day):
            continue
        for pattern, category in patterns:
            match = re.search(pattern, line)
            if match:
                event = {"time": timestamp.group(1), "timezone": timestamp.group(2), "event": category}
                if category in ("gateway_resolved", "gateway_transport_connected"):
                    event["address"] = str(ipaddress.IPv4Address(match.group(1)))
                elif category == "login_failed":
                    event["result_code"] = int(match.group(1))
                events.append(event)
                break
    return events[-100:]


def connection_check():
    """Read-only diagnosis of authentication failures, without sudo or retries."""
    folder, data = new_report("forti-connection-check")
    results = diag.batch([
        ("VPN services", ["/usr/sbin/scutil", "--nc", "list"], 6),
        ("IPv4 routes", ["/usr/sbin/netstat", "-rn", "-f", "inet"], 6),
        ("DNS", ["/usr/sbin/scutil", "--dns"], 6),
    ])
    data["stages"].append({"label": "Connection state (read-only)", "at": diag.now(), "results": results})
    raw = diag.command("FortiTray tail (not retained)", ["/usr/bin/tail", "-n", "2000", str(FORTITRAY_LOG)], 6)
    events = login_events(raw["output"], dt.datetime.now(diag.TZ).strftime("%Y%m%d")) if raw["exit_code"] == 0 else []
    processes = diag.command("Related executables (no arguments)", ["/bin/ps", "-axo", "pid=,ppid=,comm="], 6)
    processes["output"] = "\n".join(line for line in processes["output"].splitlines()
                                       if re.search(r"forti|vmware-vmx|split_tunnel|route_probe", line, re.I))
    data["stages"].append({"label": "Relevant processes", "at": diag.now(), "results": [processes]})
    routes = next(item for item in results if item["name"] == "IPv4 routes")
    entries = helper.table(routes["output"]) if routes["exit_code"] == 0 else []
    # Facts only: concurrent VMware is not proof of a VPN session inside it.
    data["connection_diagnosis"] = {
        "network_changes": False, "today_login_events": events,
        "log_read_ok": raw["exit_code"] == 0,
        "server_permission_denied_observed_today": any(e["event"] == "server_permission_denied" for e in events),
        "vm_running": "vmware-vmx" in processes["output"] if processes["exit_code"] == 0 else None,
        "broad_split_routes": [row for row in entries if row["prefix"] in helper.PREFIXES],
        "note": "Отказ после MFA не доказывает неверный код: возможны серверный тайм-аут/политика/активная сессия. "
                "Наличие VM не доказывает подключение Forti внутри неё. Сырые журналы и введённые данные не сохранены.",
    }
    data["status"] = "connection_diagnosis_no_network_changes"
    data["finished_at"] = diag.now()
    report(data, folder)
    print("Диагностика подключения сохранена; sudo, повторный вход и изменения сети не выполнялись.", flush=True)
    if data["connection_diagnosis"]["server_permission_denied_observed_today"]:
        print("В сегодняшнем журнале есть серверный отказ Permission denied. Проверьте время событий в отчёте.", flush=True)
    return 0


def load_config():
    import profile_store
    value = profile_store.read(CONFIG)
    return {"work": value["work_ipv4"], "seconds": value["session_minutes"] * 60}


def prepare():
    folder, data = new_report("split-preparation")
    private_json(PREPARED, {"ready": False})
    try:
        config = load_config()
        ops = helper.Operations()
        if ops.forti(required=False):
            raise base.ProbeError("Подготовка выполняется без подключённого FortiClient.")
        physical = ops.physical(ops.route("default").get("interface", ""))
        results = diag.batch([diag.curl_job(host, "4") for host in diag.PUBLIC_HOSTS])
        pins = diag.verified_pins(results)
        data["stages"].append({"label": "Public HTTPS before VPN", "at": diag.now(), "results": results})
        if any("4" not in pins.get(host, {}) for host in diag.PUBLIC_HOSTS):
            raise base.ProbeError("До VPN должны отвечать оба контрольных HTTPS-сайта.")
        prepared = {"ready": True, "schema": 1, "created_at": diag.now(), "public_pins": pins,
                    "config": config, **physical}
        private_json(PREPARED, prepared)
        data.update(status="prepared_no_network_changes", spec=prepared)
        print("Подготовка готова, сеть: {} / {}. Маршруты не менялись.".format(physical["interface"], physical["gateway"]), flush=True)
        return 0
    except Exception as exc:
        data.update(status="blocked_no_network_changes")
        data["notes"].append(probe.launch_output(str(exc)))
        print(data["notes"][-1], flush=True)
        return 2
    finally:
        report(data, folder)


def load_prepared():
    value = json.loads(PREPARED.read_text(encoding="utf-8"))
    if value.get("schema") != 1 or value.get("ready") is not True:
        raise base.ProbeError("Нет готовой подготовки; запустите включение сначала без VPN.")
    age = (dt.datetime.now(diag.TZ) - dt.datetime.fromisoformat(value["created_at"])).total_seconds()
    if not -60 <= age <= 24 * 3600 or value["config"] != load_config():
        raise base.ProbeError("Подготовка устарела/конфигурация изменилась. Обновите её без VPN.")
    return value


def work_connections():
    # Do not treat FortiClient/Tailscale transport peers as working-app endpoints.
    saved = diag.RELATED
    try:
        diag.RELATED = re.compile(r"trueconf|windows app|microsoft remote desktop", re.I)
        return diag.app_connections("Working application connections")
    finally:
        diag.RELATED = saved


def make_spec(prepared, ops, connections):
    context = ops.forti()
    work = set(prepared["config"]["work"])
    observed = connections.get("observed_peers", [])
    skipped = []
    for value in observed:
        address = ipaddress.ip_address(value)
        if address.version != 4:
            skipped.append(value)
            continue
        if value in (prepared["source"], prepared["gateway"], context["server"]):
            continue
        if ops.route(value).get("interface") == context["interface"]:
            work.add(value)
    spec = {"kind": helper.KIND, "seconds": prepared["config"]["seconds"],
            "work_addresses": sorted(work), "vpn_interface": context["interface"], "server": context["server"],
            **{key: prepared[key] for key in ("interface", "gateway", "source")}}
    helper.validate(spec)
    # Do not let an accidental public work address overlap the acceptance endpoints.
    pins = {value["4"] for value in prepared["public_pins"].values() if "4" in value}
    if pins & work:
        raise base.ProbeError("Контрольный интернет-адрес совпал с рабочим; нужна другая проба.")
    return spec, skipped


def control_directory():
    CONTROL_DIR.mkdir(mode=0o700, exist_ok=True)
    info = CONTROL_DIR.lstat()
    if CONTROL_DIR.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise base.ProbeError("Небезопасный каталог локального управления.")


class Controller:
    """User-only socket: stop/status without a second password during a session."""
    def __init__(self, folder, serve=True):
        control_directory()
        self.fd = os.open(str(CONTROL_DIR / "controller.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise base.ProbeError("Разделение уже запущено в другом окне.")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if CONTROL.exists():
                CONTROL.unlink()  # Stale socket owned by this user, protected by flock.
            self.sock.bind(str(CONTROL))
            CONTROL.chmod(0o600)
            self.sock.listen(2)
        except Exception:
            self.sock.close()
            os.close(self.fd)
            raise
        self.state = "starting"
        self.report_path = folder / "report.json"
        self.stop_requested = threading.Event()
        self.shutdown = threading.Event()
        self.thread = None
        if serve:
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def run(self):
        while not self.shutdown.is_set():
            if select.select([self.sock], [], [], 0.2)[0]:
                if self.receive():
                    self.stop_requested.set()

    def receive(self):
        conn, _ = self.sock.accept()
        with conn:
            conn.settimeout(1)
            try:
                value = conn.recv(32).decode("ascii").strip()
                response = {"state": self.state, "report": str(self.report_path), "pid": os.getpid()}
                conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return value == "stop"
            except (OSError, UnicodeError):
                return False

    def close(self):
        self.shutdown.set()
        if self.thread:
            self.thread.join(2)
        self.sock.close()
        if CONTROL.exists():
            CONTROL.unlink()
        os.close(self.fd)


def request_control(command):
    control_directory()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.connect(str(CONTROL))
        sock.sendall((command + "\n").encode("ascii"))
        return json.loads(sock.recv(4096).decode("utf-8"))
    except (FileNotFoundError, ConnectionRefusedError):
        return None
    finally:
        sock.close()


def start_guardian(data, spec=None, mode="lease", service=False):
    if service:
        from service_client import ServiceGuardian
        return ServiceGuardian(spec, data["guardian_events"], mode=mode)
    return probe.Guardian({}, data["guardian_events"], mode=mode,
                          helper_path=ROOT / "split_tunnel_helper.py", request=spec)


def confirm_plan(controller):
    print("Введите ДА для применения этого плана: ", end="", flush=True)
    while not controller.stop_requested.is_set():
        if select.select([sys.stdin], [], [], 0.2)[0]:
            return sys.stdin.readline().strip().upper() == "ДА"
    return False


def acceptance(prepared, spec):
    jobs = []
    for host in diag.PUBLIC_HOSTS:
        jobs += [diag.curl_job(host, "4"), diag.curl_job(host, "4", prepared["public_pins"][host]["4"])]
    jobs += [diag.route_job(ip) for ip in spec["work_addresses"]]
    jobs += [diag.route_job(value["4"]) for value in prepared["public_pins"].values()]
    results = diag.batch(jobs)
    passed = {}
    for item in results:
        if item["name"].startswith("HTTPS "):
            fields = dict(re.findall(r"^(\w+)=(\S*)$", item["output"], re.M))
            passed[item["name"]] = (item["exit_code"] == 0 and fields.get("tls_verify") == "0"
                                    and fields.get("http_code", "000") != "000")
        else:
            route = base.parse_route(item["output"])
            address = item["name"][6:]
            interface = spec["vpn_interface"] if address in spec["work_addresses"] else spec["interface"]
            passed[item["name"]] = item["exit_code"] == 0 and route.get("interface") == interface
    return {"ok": bool(passed) and all(passed.values()), "checks": passed}, results


def wait_session(guardian, controller, data, folder):
    controller.state = "active"
    print("РАЗДЕЛЕНИЕ ВКЛЮЧЕНО. Проверьте браузер, Windows App и звонок TrueConf.", flush=True)
    print("Для отключения нажмите Enter здесь или запустите «Выключить разделение.command».", flush=True)
    print("Приложение/окно оставьте открытым. Изменение VPN/сети или сон завершают сеанс с откатом.", flush=True)
    while True:
        if controller.stop_requested.is_set():
            return "stop_command"
        readers = [guardian.process.stdout]
        if sys.stdin.isatty():
            readers.append(sys.stdin)
        ready, _, _ = select.select(readers, [], [], 1)
        if sys.stdin in ready:
            sys.stdin.readline()
            return "enter"
        if guardian.process.stdout in ready:
            event = guardian.read_event(2)
            report(data, folder)
            if event.get("event") in ("error", "lease_end", "rolled_back", "rollback_error"):
                data["end_event"] = event["event"]
                return event.get("reason", event.get("message", event["event"]))


def session_outcome(data):
    """GUI protocol, not a translation/parsing of diagnostic stdout or exit code."""
    if data.get("status") == "rollback_unconfirmed":
        return "recovery_required"
    restored = (data.get("status") == "complete_rolled_back"
                and data.get("rollback", {}).get("event") == "rolled_back"
                and data.get("rollback", {}).get("rollback", {}).get("ok") is True)
    if restored and data.get("session_was_active") is True and not data.get("session_failed") \
            and data.get("exit_code") in (0, 2) \
            and data.get("end_event") in ("error", "lease_end", "rolled_back"):
        # The guard ends an active lease on VPN/network/sleep changes. Its exit
        # code is deliberately nonzero; confirmed rollback is not a GUI failure.
        return "connection_ended"
    if restored and data.get("exit_code") in (0, 130):
        return "stopped"
    return "failed"


def session(dry_run=False, gui=False):
    folder, data = new_report("split-check" if dry_run else "split-session")
    guardian, controller = None, None
    code = 0
    try:
        # Lock the user controller before sudo or any mutation.
        controller = Controller(folder)
        prepared = load_prepared()
        ops = helper.Operations()
        connections = work_connections()
        data["stages"].append(connections)
        spec, skipped = make_spec(prepared, ops, connections)
        data["spec"] = spec
        if skipped:
            data["notes"].append("Наблюдаемые IPv6 остаются в VPN без изменений: " + ", ".join(skipped))
        data["plan"] = helper.SplitLease(spec, ops=ops).plan()
        report(data, folder)
        duration = "без лимита времени" if not spec["seconds"] else "{} минут".format(spec["seconds"] // 60)
        print("План: {} рабочих/DNS адресов в VPN; IPv4 /1 через {}; {}.".format(
            len(data["plan"]["protected_addresses"]), spec["gateway"], duration), flush=True)
        if dry_run:
            data["status"] = "dry_run_no_network_changes"
            return 0
        print("DNS и IPv6 не меняются. Изменения временные, без установки службы/автозапуска.", flush=True)
        if not gui and not sys.stdin.isatty():
            raise base.ProbeError("Включение разрешено только из интерактивного Terminal.")
        if not gui and not confirm_plan(controller):
            data["status"] = "cancelled_no_network_changes"
            return 0
        if controller.stop_requested.is_set():
            data["status"] = "cancelled_no_network_changes"
            return 0
        data["authentication"] = {"exit_code": 0, "method": "installed_helper"} if gui else probe.authenticate_sudo()
        if data["authentication"]["exit_code"] != 0:
            raise base.ProbeError("Права администратора не получены.")
        if controller.stop_requested.is_set():
            data["status"] = "cancelled_no_network_changes"
            return 0
        guardian = start_guardian(data, spec, service=gui)
        ready = guardian.ready()
        data.update(status="applied_testing", plan=ready["plan"])
        report(data, folder)
        if controller.stop_requested.is_set():
            raise base.ProbeError("Получен запрос отключения; выполняется откат.")
        checks, results = acceptance(prepared, spec)
        data["acceptance"] = checks
        data["stages"].append({"label": "Automatic IPv4 acceptance", "at": diag.now(), "results": results})
        if not checks["ok"]:
            raise base.ProbeError("Не все проверки HTTPS/маршрутов прошли; автоматический откат.")
        data["status"] = "active_ipv4_manual_app_checks_required"
        data["session_was_active"] = True
        report(data, folder)
        data["end_reason"] = wait_session(guardian, controller, data, folder)
        # App sockets are observations, not proof of a successful call or RDP session.
        data["stages"].append(work_connections())
    except (KeyboardInterrupt, EOFError):
        code = 130
        data["notes"].append("Остановлено пользователем.")
    except Exception as exc:
        code = 2
        data["session_failed"] = True
        data["notes"].append(probe.launch_output(str(exc)))
        print(data["notes"][-1], flush=True)
    finally:
        if guardian:
            if controller:
                controller.state = "rolling_back"
            # Ctrl+C during rollback must not close the parent pipe prematurely.
            previous = {}
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, signal.SIG_IGN)
            try:
                final = guardian.release()
                data["rollback"] = final
                data["helper_exit_code"] = guardian.process.returncode
                confirmed = bool(final and final.get("event") == "rolled_back" and final["rollback"].get("ok"))
                not_started = bool(final and final.get("event") == "not_started")
                data["status"] = ("complete_rolled_back" if confirmed else
                                  "helper_not_started_no_changes" if not_started else "rollback_unconfirmed")
                if not confirmed:
                    code = 2 if not_started else 3
                elif guardian.process.returncode != 0:
                    code = 2
                print("Откат подтверждён." if confirmed else "Откат НЕ подтверждён. Запустите «Выключить разделение.command».", flush=True)
            except Exception as exc:
                code = 3
                data.update(status="rollback_unconfirmed")
                data["notes"].append(probe.launch_output(str(exc)))
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
        elif data["status"] == "started":
            data["status"] = "blocked_no_network_changes"
        data["exit_code"] = code
        data["finished_at"] = diag.now()
        try:
            report(data, folder)
        finally:
            if controller:
                controller.close()
        print("Результат: {}. Отчёт: {}".format(data["status"], folder / "report.txt"), flush=True)
        if gui:
            print("FORTI_SPLIT_RESULT " + json.dumps({"schema": 1, "action": "enable", "pid": os.getpid(),
                                                       "outcome": session_outcome(data)}), flush=True)
    return code


def stop():
    state = request_control("stop")
    if state:
        print("Запрос отключения отправлен. Жду подтверждения отката в основном окне…", flush=True)
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            # Do not queue requests while the parent is busy with its rollback.
            if not CONTROL.exists():
                final = json.loads(Path(state["report"]).read_text(encoding="utf-8"))
                rollback = final.get("rollback", {})
                no_changes = final.get("status") in ("cancelled_no_network_changes", "blocked_no_network_changes",
                                                      "dry_run_no_network_changes", "helper_not_started_no_changes")
                ok = no_changes or (rollback.get("event") == "rolled_back" and rollback.get("rollback", {}).get("ok") is True)
                print("Откат подтверждён." if ok else "Откат НЕ подтверждён; проверьте отчёт.", flush=True)
                print("Отчёт: " + state["report"], flush=True)
                return 0 if ok else 3
            time.sleep(1)
        raise base.ProbeError("Контроллер ещё работает. Проверьте основное окно; второй помощник не запускался.")
    return recover()


def recover(no_prompt=False, service=False):
    """Recover only the root journal; never send stop to a live controller."""
    folder, data = new_report("split-recovery")
    guardian = None
    try:
        data["authentication"] = {"exit_code": 0, "method": "installed_helper"} if service else probe.authenticate_sudo(no_prompt=no_prompt)
        if data["authentication"]["exit_code"] != 0:
            raise base.ProbeError("Для восстановления нужны права администратора.")
        guardian = start_guardian(data, mode="recover", service=service)
        final = guardian.release(send=False)
        data["rollback"] = final
        ok = bool(final and final.get("event") == "rolled_back" and final["rollback"].get("ok"))
        data["status"] = "recovered" if ok else "rollback_unconfirmed"
        print("Откат подтверждён." if ok else "Откат НЕ подтверждён; нужен разбор отчёта.", flush=True)
        return 0 if ok else 3
    except Exception as exc:
        data["status"] = "recovery_failed"
        data["notes"].append(probe.launch_output(str(exc)))
        print(data["notes"][-1], flush=True)
        return 3
    finally:
        report(data, folder)


def terminated(signum, frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("prepare", "dry-run", "apply", "stop", "status", "connection-check", "recover"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--gui", action="store_true", help="GUI confirmation; installed narrow privileged helper only")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Контроллер запускается обычным пользователем; sudo нужен только помощнику.")
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, terminated)
    try:
        if args.prepare:
            return prepare()
        if args.connection_check:
            return connection_check()
        if args.stop:
            return stop()
        if args.recover:
            return recover(service=args.gui)
        if args.status:
            print("Контроллер: " + str(request_control("status") or "не запущен; это не проверка отсутствия остаточных маршрутов"))
            return 0
        if args.interactive:
            if not sys.stdin.isatty():
                raise base.ProbeError("Запустите .command в Terminal.")
            print("FortiClient пока должен быть ОТКЛЮЧЁН.", flush=True)
            if prepare() != 0 or probe.self_test(helper_path=ROOT / "split_tunnel_helper.py") != 0:
                return 2
            print("Проверка/закрытие незавершённого журнала до подключения VPN…", flush=True)
            if recover(no_prompt=True) != 0:
                print("Восстановление не подтверждено. Пока не подключайте VPN.", flush=True)
                return 3
            response = input("Теперь подключите FortiClient, дождитесь готовности, откройте Windows App и TrueConf. "
                             "Enter — продолжить; ОШИБКА — сохранить диагностику без изменений сети: ").strip()
            if response:
                if response.upper() in ("ОШИБКА", "ERROR"):
                    return connection_check()
                print("Отменено. Разделение не применялось.", flush=True)
                return 0
            try:
                helper.Operations().forti()
            except base.ProbeError:
                print("FortiClient не подключён. Сохраню диагностику вместо попытки применения.", flush=True)
                connection_check()
                return 2
        return session(dry_run=args.dry_run, gui=True) if args.gui else session(dry_run=args.dry_run)
    except (KeyboardInterrupt, EOFError):
        print("Остановлено до начала сеанса.", flush=True)
        return 130
    except Exception as exc:
        print(probe.launch_output(str(exc)), flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
