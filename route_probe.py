#!/usr/bin/python3
"""Offline one-address routing experiment, with an independent privileged guardian."""

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

import route_probe_helper as helper
import vpn_diagnostics as diag


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "diagnostics"
PREPARED = OUTPUT / "route-probe-prepared.json"
HOST = "example.com"


class HelperNotStarted(helper.ProbeError):
    """A nonzero launcher exit without the helper's pre-mutation hello."""


def launch_output(text):
    # These exact sudo diagnostics contain no credential values. The generic
    # collector's blanket 'password' filter must not hide the reason for failure.
    safe = {"sudo: a password is required", "sudo: timed out reading password",
            "sudo: no tty present and no askpass program specified",
            "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper"}
    lines = []
    for line in text.splitlines():
        if line.strip() in safe or re.fullmatch(r"sudo: \d+ incorrect password attempts?", line.strip()):
            lines.append(line.strip())
        else:
            lines.append(diag.clean_output(line))
    return "\n".join(lines)


def authenticate_sudo(no_prompt=False):
    if not no_prompt and sys.stdin.isatty():
        print("Введите пароль администратора Mac в системный sudo (ввод не отображается).", flush=True)
        completed = subprocess.run(["/usr/bin/sudo", "-v"])
        return {"interactive": True, "exit_code": completed.returncode}
    completed = subprocess.run(["/usr/bin/sudo", "-n", "-v"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, errors="replace", timeout=8)
    return {"interactive": False, "exit_code": completed.returncode,
            "output": launch_output(completed.stdout)}


def persist(folder, data):
    heading = "FORTICLIENT: ПРОБА ОДНОГО ПУБЛИЧНОГО МАРШРУТА"
    if data.get("kind") == "helper-health":
        heading = "ПРОВЕРКА SUDO И ПОМОЩНИКА БЕЗ VPN И ИЗМЕНЕНИЯ МАРШРУТОВ"
    lines = [heading, "Начало: " + data["started_at"],
             "Статус: " + data["status"], "Результат: " + data.get("result", "ещё не определён"),
             "Тест временный. Общий маршрут, DNS и рабочие назначения не перенастраиваются.",
             "Приватный отчёт: внутренние IP и имена серверов не предназначены для публикации."]
    if data.get("spec"):
        lines += ["Параметры:", json.dumps(data["spec"], ensure_ascii=False, indent=2)]
    for key in ("authentication", "health_checks"):
        if key in data:
            lines += [key + ":", json.dumps(data[key], ensure_ascii=False, indent=2)]
    lines += ["ПРИМЕЧАНИЕ: " + note for note in data.get("notes", [])]
    for stage in data.get("stages", []):
        lines.extend(diag.render_stage(stage))
    lines.append("\n=== СОБЫТИЯ ОТДЕЛЬНОГО ПРОЦЕССА ОТКАТА ===")
    lines += [json.dumps(event, ensure_ascii=False, indent=2) for event in data.get("guardian_events", [])]
    for name, text in (("report.txt", "\n".join(lines) + "\n"),
                       ("report.json", json.dumps(data, ensure_ascii=False, indent=2) + "\n")):
        temporary = folder / (name + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(str(temporary), str(folder / name))


def new_report(mode):
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    folder = OUTPUT / (mode + "-" + dt.datetime.now(diag.TZ).strftime("%Y%m%d-%H%M%S-%f"))
    folder.mkdir(mode=0o700)
    data = {"kind": mode, "started_at": diag.now(), "status": "started", "notes": [], "stages": [],
            "guardian_events": []}
    persist(folder, data)
    print("Отчёт: {}".format(folder / "report.txt"), flush=True)
    return folder, data


def add_stage(folder, data, label, results):
    data["stages"].append({"label": label, "at": diag.now(), "results": results})
    persist(folder, data)


def known_work_addresses():
    for folder in sorted(OUTPUT.glob("connected-*"), reverse=True):
        try:
            data = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            if data.get("status") != "complete":
                continue
            addresses = set()
            for stage in data.get("stages", []):
                addresses.update(stage.get("observed_peers", []))
                for item in stage.get("results", []):
                    if item["name"] == "DNS":
                        addresses.update(diag.dns_server_addresses(item["output"]))
                    if item["name"] == "IPv4 routes":
                        for line in item["output"].splitlines():
                            fields = line.split()
                            if len(fields) >= 4 and "S" in fields[2] and "H" in fields[2] \
                                    and fields[3].startswith("utun"):
                                addresses.add(fields[0].removesuffix("/32"))
            return sorted(address for address in addresses
                          if diag.is_ip(address) and ipaddress.ip_address(address).version == 4)[:24]
        except (OSError, ValueError, KeyError):
            continue
    return []


def prepare():
    folder, data = new_report("probe-preparation")
    # Mark the current preparation unavailable even if a previous one existed.
    # Historical preparation reports remain intact.
    PREPARED.write_text(json.dumps({"schema": 1, "ready": False, "created_at": diag.now()}), encoding="utf-8")
    PREPARED.chmod(0o600)
    try:
        ops = helper.Operations()
        if ops.forti(required=False):
            raise helper.ProbeError("Подготовка выполняется при отключённом FortiClient.")
        interface = ops.route("default").get("interface", "")
        physical = ops.physical(interface)
        test = diag.command(*diag.curl_job(HOST, "4"))
        add_stage(folder, data, "HTTPS before VPN", [test])
        address = diag.verified_pins([test]).get(HOST, {}).get("4")
        if not address or not ipaddress.IPv4Address(address).is_global:
            raise helper.ProbeError("Не удалось проверить публичный HTTPS до VPN; подготовка не сохранена.")
        work = known_work_addresses()
        if address in work:
            raise helper.ProbeError("Тестовый адрес совпал с наблюдаемым рабочим назначением.")
        prepared = {"schema": 1, "ready": True, "created_at": diag.now(), "host": HOST, "target": address,
                    **physical, "protected_addresses": work, "preparation_report": str(folder / "report.txt")}
        temporary = PREPARED.with_suffix(".tmp")
        temporary.write_text(json.dumps(prepared, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(str(temporary), str(PREPARED))
        data.update(status="complete", result="prepared", spec=prepared)
        persist(folder, data)
        print("Подготовка готова: {} -> {} через {} / {}".format(
            HOST, address, physical["gateway"], interface))
        return 0
    except Exception as exc:
        data.update(status="blocked", result="not_prepared")
        data["notes"].append(diag.clean_output(str(exc)))
        persist(folder, data)
        print("Подготовка остановлена: " + data["notes"][-1])
        return 2


def load_prepared():
    prepared = json.loads(PREPARED.read_text(encoding="utf-8"))
    if prepared.get("schema") != 1 or prepared.get("host") != HOST or prepared.get("ready") is not True:
        raise helper.ProbeError("Нет успешно завершённой подготовки. Обновите её без VPN.")
    age = dt.datetime.now(diag.TZ) - dt.datetime.fromisoformat(prepared["created_at"])
    if age.total_seconds() < -60 or age.total_seconds() > 24 * 3600:
        raise helper.ProbeError("Подготовке больше суток/системное время изменилось. Обновите её без VPN.")
    if not ipaddress.IPv4Address(prepared["target"]).is_global:
        raise helper.ProbeError("Неверный публичный тестовый IP.")
    return prepared


def preflight(prepared, ops=None):
    ops = ops or helper.Operations()
    context = ops.forti()
    physical = ops.physical(prepared["interface"], prepared["gateway"], prepared["source"])
    spec = {"target": prepared["target"], **physical, "vpn_interface": context["interface"]}
    helper.validate_spec(spec)
    if spec["target"] in prepared.get("protected_addresses", []) or spec["target"] == context["server"]:
        raise helper.ProbeError("Тестовый IP совпал с рабочим назначением или VPN-сервером.")
    if ops.route(spec["target"]).get("interface") != context["interface"]:
        raise helper.ProbeError("Тестовый адрес уже идёт вне FortiClient; проба не требуется.")
    return spec


def route_summary(results):
    return {item["name"]: helper.parse_route(item["output"]) for item in results
            if item["name"].startswith("route ") and item["exit_code"] == 0}


def route_identity(route):
    # Kernel host-cache creation may change destination/default without changing
    # the actual next hop. Compare the selected interface and gateway.
    return {key: route.get(key) for key in ("gateway", "interface")}


class Guardian:
    def __init__(self, spec, events, mode="lease", helper_path=None, request=None):
        if mode not in ("lease", "health", "recover"):
            raise ValueError("Неизвестный режим помощника")
        self.mode = mode
        self.started = False
        self.eof = False
        self.buffer = b""
        self.events = events
        self.event_start = len(events)
        argv = ["/usr/bin/sudo", "-n", "/usr/bin/python3", str(helper_path or ROOT / "route_probe_helper.py"), mode]
        for key, value in spec.items():
            argv += ["--" + key.replace("_", "-"), value]
        env = os.environ.copy()
        env.update({"LC_ALL": "C", "LANG": "C"})
        # Keep sudo in the authenticated terminal session. The helper remains a
        # separate process; HUP/TERM handling and pipe EOF still trigger rollback.
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0,
                                        start_new_session=False, env=env)
        if request is not None:
            self.process.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
            self.process.stdin.flush()

    def process_exit(self):
        try:
            code = self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            code = None
        if not self.eof:
            self.events.append({"event": "process_exit", "exit_code": code, "helper_started": self.started})
            self.eof = True
        if not self.started and code is not None and code != 0:
            raise HelperNotStarted("Помощник не запустился (код {}). Маршрутная проба не начиналась; "
                                   "причина запуска сохранена в событиях отчёта.".format(code))
        raise helper.ProbeError("Процесс помощника закрыл канал без ожидаемого подтверждения.")

    def read_event(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {"event": "message", "text": launch_output(line.decode("utf-8", errors="replace"))}
                if not isinstance(event, dict):
                    event = {"event": "message", "text": "Неожиданный формат ответа помощника"}
                if event.get("event") == "hello":
                    self.started = True
                self.events.append(event)
                return event
            if self.eof:
                self.process_exit()
            remaining = max(0, deadline - time.monotonic())
            if not select.select([self.process.stdout], [], [], remaining)[0]:
                break
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                # Some launchers write their last error without a trailing newline.
                if self.buffer:
                    self.buffer += b"\n"
                    continue
                self.process_exit()
            self.buffer += chunk
        raise helper.ProbeError("Не получено подтверждение от процесса отката в отведённое время.")

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            event = self.read_event(max(0.1, deadline - time.monotonic()))
            if event.get("event") == "hello":
                if (event.get("protocol") != helper.PROTOCOL_VERSION or event.get("uid") != 0
                        or event.get("mode") != self.mode):
                    raise helper.ProbeError("Версия/права/режим помощника не соответствуют ожидаемым.")
            if event.get("event") == "error":
                raise helper.ProbeError(event.get("message", "Ошибка помощника"))
            if event.get("event") == "ready":
                if not self.started:
                    raise helper.ProbeError("Нет стартового подтверждения помощника.")
                if self.mode == "lease" and event.get("remaining_seconds", 0) is not None and event.get("remaining_seconds", 0) < 35:
                    raise helper.ProbeError("Недостаточно времени на безопасную проверку; выполняется откат.")
                return event
        raise helper.ProbeError("Помощник не подтвердил маршрут.")

    def release(self, send=True):
        if not self.process.stdin.closed:
            try:
                if send:
                    self.process.stdin.write(b"release\n")
                    self.process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            self.process.stdin.close()
        if not self.started and self.eof:
            code = self.process.wait(timeout=5)
            if code != 0:
                self.process.stdout.close()
                return {"event": "not_started", "exit_code": code, "network_changes": False}
        # If ready() consumed a final event, do not wait for an already delivered one.
        final_names = {"health_complete"} if self.mode == "health" else {"rolled_back", "rollback_error"}
        final = next((event for event in reversed(self.events[self.event_start:])
                      if event.get("event") in final_names), None)
        deadline = time.monotonic() + 35
        while final is None and time.monotonic() < deadline:
            event = self.read_event(max(0.1, deadline - time.monotonic()))
            if event.get("event") in final_names:
                final = event
        self.process.wait(timeout=5)
        self.process.stdout.close()
        return final


def self_test(no_prompt=False, helper_path=None):
    """Real sudo/helper handshake and guardian timing, no route/VPN commands."""
    folder, data = new_report("helper-health")
    data.update(network_changes=False, health_checks=[])
    guardian = None
    code = 0
    try:
        print("Проверка запуска без VPN. Маршруты, DNS и журнал маршрутной пробы не затрагиваются.", flush=True)
        auth = authenticate_sudo(no_prompt)
        data["authentication"] = auth
        persist(folder, data)
        if auth["exit_code"] != 0:
            data.update(status="authentication_required", result="helper_not_tested_no_changes")
            data["notes"].append("Запустите «Проверить запуск помощника.command» в Terminal без VPN "
                                 "и введите пароль администратора там. Пароль в чат не отправляется.")
            return 2
        for scenario in ("release", "parent_eof", "deadline"):
            print("Связь с помощником: {}...".format(scenario), flush=True)
            guardian = Guardian({}, data["guardian_events"], mode="health", helper_path=helper_path)
            guardian.ready()
            if scenario == "deadline":
                limit = time.monotonic() + 8
                while time.monotonic() < limit:
                    event = guardian.read_event(max(0.1, limit - time.monotonic()))
                    if event.get("event") == "health_complete":
                        break
            final = guardian.release(send=scenario == "release")
            if (not final or final.get("event") != "health_complete" or not final.get("ok")
                    or final.get("reason") != scenario or final.get("network_changes") is not False):
                raise helper.ProbeError("Помощник не подтвердил безопасное завершение сценария " + scenario)
            data["health_checks"].append({"scenario": scenario, "ok": True, "network_changes": False})
            guardian = None
            persist(folder, data)
        data.update(status="complete", result="helper_health_passed")
        print("ПРОВЕРКА ПРОЙДЕНА: sudo, запуск помощника, закрытие канала и таймер работают.", flush=True)
    except (KeyboardInterrupt, EOFError):
        code = 130
        data.update(status="interrupted", result="helper_health_not_passed")
        data["notes"].append("Проверка запуска прервана; маршрутные операции не выполнялись.")
    except Exception as exc:
        code = 2
        data.update(status="failed", result="helper_health_not_passed")
        data["notes"].append(launch_output(str(exc)))
        print(data["notes"][-1], flush=True)
    finally:
        if guardian:
            try:
                guardian.release()
            except Exception as exc:
                data["notes"].append("Завершение диагностического помощника: " + launch_output(str(exc)))
        data["finished_at"] = diag.now()
        persist(folder, data)
        print("Проверка без изменения сети. Отчёт: {}".format(folder / "report.txt"), flush=True)
    if code:
        print("Пока не подключайте VPN для повторной пробы: сначала разберём этот отчёт.", flush=True)
    return code


def probe(apply):
    folder, data = new_report("route-probe" if apply else "route-probe-check")
    guardian = None
    code = 0
    try:
        prepared = load_prepared()
        spec = preflight(prepared)
        data["spec"] = spec
        persist(folder, data)
        if not apply:
            data.update(status="complete", result="preflight_passed_no_changes")
            return 0
        print("Проверки условий пройдены. Нужен пароль администратора Mac в Terminal.", flush=True)
        data["authentication"] = authenticate_sudo()
        if data["authentication"]["exit_code"] != 0:
            raise helper.ProbeError("Права администратора не получены; маршруты не менялись.")
        protected = prepared.get("protected_addresses", [])
        route_jobs = [diag.route_job(address) for address in protected] + [diag.route_job("1.1.1.1")]
        before = diag.batch(route_jobs + [("DNS", ["/usr/sbin/scutil", "--dns"], 6)])
        add_stage(folder, data, "Protected routes and DNS BEFORE", before)
        applications = diag.app_connections("before")
        add_stage(folder, data, "Application connections BEFORE", applications["results"])
        if spec["target"] in applications.get("observed_peers", []):
            raise helper.ProbeError("Рабочее приложение сейчас использует тестовый IP; маршрут не изменён.")
        first = diag.command(*diag.curl_job(HOST, "4", spec["target"]))
        add_stage(folder, data, "HTTPS through VPN BEFORE", [first])
        # Validate again after sudo and the pre-test; user may have changed VPN/network.
        preflight(prepared)
        print("Временная проба одного адреса. По завершении маршрут будет возвращён.", flush=True)
        data["status"] = "starting_guardian"
        persist(folder, data)
        guardian = Guardian(spec, data["guardian_events"])
        ready = guardian.ready()
        data["status"] = "temporary_route_active"
        persist(folder, data)
        during = diag.command(*diag.curl_job(HOST, "4", spec["target"]))
        add_stage(folder, data, "HTTPS with temporary route (unbound application)", [during])
        unchanged = diag.batch(route_jobs + [("DNS", ["/usr/sbin/scutil", "--dns"], 6),
                                            diag.route_job(spec["target"])])
        add_stage(folder, data, "Protected routes, DNS and target DURING", unchanged)
        prior, current = route_summary(before), route_summary(unchanged)
        same_routes = all(name in current and route_identity(value) == route_identity(current[name])
                          for name, value in prior.items()) and len(prior) == len(route_jobs)
        dns_before = next(item for item in before if item["name"] == "DNS")
        dns_after = next(item for item in unchanged if item["name"] == "DNS")
        same_dns = dns_before["exit_code"] == dns_after["exit_code"] == 0 \
            and dns_before["output"] == dns_after["output"]
        data["protected_routes_unchanged"] = same_routes
        data["dns_unchanged"] = same_dns
        target_route = current.get("route " + spec["target"], {})
        target_direct = target_route.get("interface") == spec["interface"] \
            and target_route.get("gateway") == spec["gateway"]
        passed = bool(diag.verified_pins([dict(during, name="HTTPS " + HOST + " IPv4 system DNS")]))
        before_passed = bool(diag.verified_pins([dict(first, name="HTTPS " + HOST + " IPv4 system DNS")]))
        if before_passed:
            data["notes"].append("HTTPS работал ещё до изменения маршрута; причинная связь с пробой не установлена.")
        data["result"] = "direct_https_passed" if passed and target_direct and same_routes and same_dns \
            and not before_passed else "inconclusive_or_failed"
        if not passed:
            # Same destination only; this is a separate diagnostic, not evidence that
            # ordinary unbound apps can use a future destination-based split tunnel.
            job = diag.curl_job(HOST, "4", spec["target"])
            bound_argv = job[1][:-1] + ["--interface", spec["interface"], job[1][-1]]
            bound = diag.command("HTTPS bound to physical interface (additional diagnostic)", bound_argv, 11)
            add_stage(folder, data, "Optional explicitly bound HTTPS", [bound])
        if not same_routes or not same_dns:
            data["notes"].append("Во время пробы изменились рабочие маршруты/DNS. Причину нужно проверить; результат не принят как успех.")
        data["status"] = "tests_finished_waiting_for_rollback"
    except (KeyboardInterrupt, EOFError):
        code = 130
        data.update(status="interrupted", result="inconclusive_or_failed")
        data["notes"].append("Проба прервана пользователем. Запрошен откат.")
    except Exception as exc:
        code = 2
        data.update(status="blocked_or_error", result="inconclusive_or_failed")
        data["notes"].append(diag.clean_output(str(exc)))
        print(data["notes"][-1], flush=True)
    finally:
        if guardian:
            for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, signal.SIG_IGN)
            final = None
            try:
                final = guardian.release()
                rolled_back = bool(final and final.get("event") == "rolled_back"
                                   and final.get("rollback", {}).get("ok"))
            except Exception as exc:
                rolled_back = False
                data["notes"].append("Нет подтверждения отката: " + str(exc))
            data["rollback_confirmed"] = rolled_back
            if final and final.get("event") == "not_started":
                data.update(status="helper_not_started_no_changes", result="helper_launch_failed")
                data["network_changes"] = False
                data.pop("rollback_confirmed", None)
                code = 2
                print("Помощник не запустился. Маршрутная проба не начиналась; откат не требуется.", flush=True)
            elif rolled_back:
                data["status"] = "complete_rolled_back" if code == 0 else "stopped_rolled_back"
                effective = final.get("rollback", {}).get("effective", {})
                if data.get("result") == "direct_https_passed" \
                        and effective.get("interface") != data["spec"]["vpn_interface"]:
                    data["result"] = "inconclusive_or_failed"
                    data["notes"].append("После удаления пробы путь через прежний VPN не подтверждён; "
                                         "возможно, VPN отключился/переподключился во время теста.")
                print("Откат подтверждён: временного маршрута нет.", flush=True)
            else:
                code = 3
                data.update(status="rollback_unconfirmed", result="inconclusive_or_failed")
                print("Откат не подтверждён. Запустите «Вернуть маршрут.command».", flush=True)
        data["finished_at"] = diag.now()
        persist(folder, data)
    print("Результат: {}\nОтчёт: {}".format(data.get("result"), folder / "report.txt"), flush=True)
    if apply:
        print("Это временная проверка. Отключите FortiClient и напишите в чате: «Прочитай результат пробы».")
    return code


def recover():
    folder, data = new_report("route-probe-recovery")
    if subprocess.run(["/usr/bin/sudo", "-v"]).returncode != 0:
        data.update(status="blocked", result="sudo_not_available")
        persist(folder, data)
        return 2
    item = diag.command("Recover journaled probe route", ["/usr/bin/sudo", "-n", "/usr/bin/python3",
                         str(ROOT / "route_probe_helper.py"), "recover"], 40)
    data.update(status="complete" if item["exit_code"] == 0 else "recovery_needs_review",
                result="see_guardian_output")
    add_stage(folder, data, "Recovery", [item])
    print(item["output"], flush=True)
    return 0 if item["exit_code"] == 0 else 3


def main():
    parser = argparse.ArgumentParser(description="Проба одного публичного IPv4 с независимым откатом.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="подготовить пробу при отключённом VPN; без изменений сети")
    modes.add_argument("--apply", action="store_true", help="временно изменить один host-маршрут, выполнить тест и откат")
    modes.add_argument("--recover", action="store_true", help="откатить только запись из журнала незавершённой пробы")
    modes.add_argument("--check", action="store_true", help="проверить условия при VPN без изменения маршрутов")
    modes.add_argument("--self-test", action="store_true", help="проверить sudo и помощника без VPN и изменения маршрутов")
    parser.add_argument("--interactive", action="store_true", help="дождаться Enter после подключения VPN")
    parser.add_argument("--no-prompt", action="store_true", help="не запрашивать пароль; только доступный кэш sudo")
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() == 0:
        parser.error("Запускайте этот файл обычным пользователем: sudo вызывается только для отдельного помощника.")
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, interrupted)
    if args.self_test:
        return self_test(args.no_prompt)
    print("Автономная временная проба. Постоянное разделение трафика не включается.", flush=True)
    if args.apply:
        # Validate the privileged launch BEFORE asking the user to connect a VPN.
        code = self_test(args.no_prompt)
        if code:
            return code
    if args.interactive and not args.prepare and not args.recover:
        print("Подключите FortiClient НА MAC и откройте рабочие приложения. Сеть Wi-Fi должна быть той же.")
        try:
            input("Когда VPN полностью подключится, нажмите Enter (Ctrl+C — отмена): ")
        except (KeyboardInterrupt, EOFError):
            return 130
    if args.prepare:
        return prepare()
    if args.recover:
        return recover()
    return probe(args.apply)


if __name__ == "__main__":
    sys.exit(main())
