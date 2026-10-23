#!/usr/bin/python3
"""Unprivileged backend for the small AppKit frontend."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading
import json_codec
import macos_preflight
import setup_flow

import route_probe as probe
import service_client
import service_paths
import split_tunnel as app
import split_tunnel_helper as helper
import vpn_diagnostics as diag
import profile_store

FORTI_PATH = None


def configure(directory):
    directory = profile_store.secure_directory(Path(directory).absolute())
    app.OUTPUT = directory / "diagnostics"
    app.PREPARED = app.OUTPUT / "split-prepared.json"
    app.CONFIG = directory / "split-config.json"
    probe.OUTPUT = diag.OUTPUT = app.OUTPUT
    profile_store.secure_directory(app.OUTPUT)


def health_path():
    return app.CONFIG.parent / "helper-health.json"


def helper_healthy(service):
    try:
        path = health_path()
        if path.is_symlink() or path.stat().st_size > 4096:
            return False
        saved = json_codec.loads(path.read_text())
        return (service.get("installed") is True and service.get("current") is True
                and saved.get("ok") is True and saved.get("digest") == service.get("digest"))
    except (OSError, ValueError, AttributeError):
        return False


def state():
    result = {"service": service_client.status(), "vpn": None, "prepared": False, "session": None,
              "latest_report": None, "latest_status": None, "rollback_ok": None}
    if result["service"].get("installed"):
        result["service"]["current"] = result["service"].get("digest") == service_paths.digest(app.ROOT)
    result["helper_healthy"] = helper_healthy(result["service"])
    preflight = macos_preflight.snapshot(FORTI_PATH)
    result["platform"] = preflight.pop("platform")
    result["preflight"] = preflight
    try:
        config = app.load_config()
        result["profile"] = {"ready": True, "count": len(config["work"])}
    except Exception:
        result["profile"] = {"ready": False, "message": "Выберите корректный приватный JSON-профиль."}
    try:
        result["vpn"] = helper.Operations().forti(required=False)
    except helper.base.ProbeError as exc:
        result["vpn_error"] = str(exc)
    try:
        prepared = app.load_prepared()
        helper.Operations().physical(prepared["interface"], prepared["gateway"], prepared["source"])
        result["prepared"] = True
    except Exception as exc:
        result["preparation_error"] = str(exc)
    try:
        result["session"] = app.request_control("status")
    except OSError:
        pass
    reports = sorted((path for pattern in ("split-session-*/report.json", "split-recovery-*/report.json")
                      for path in app.OUTPUT.glob(pattern)), reverse=True)
    # Directory names include a different mode prefix; select by timestamp, not
    # prefix lexicographic order, so successful recovery clears a stale warning.
    reports.sort(key=lambda path: path.parent.name.rsplit("-", 3)[-3:], reverse=True)
    if reports:
        try:
            if reports[0].is_symlink() or reports[0].stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Invalid local report")
            latest = json_codec.loads(reports[0].read_text())
            result.update(latest_report=str(reports[0].with_suffix(".txt")), latest_status=latest.get("status"),
                          rollback_ok=latest.get("rollback", {}).get("rollback", {}).get("ok"))
        except (OSError, ValueError, AttributeError, TypeError):
            pass
    result["flow"] = setup_flow.flow(result)
    return result


def watch_gui():
    # The app owns stdin's write end. Window close/force quit/crash -> EOF ->
    # orderly backend SIGTERM -> socket EOF/release -> independent root rollback.
    try:
        os.read(sys.stdin.fileno(), 1)
    finally:
        os.kill(os.getpid(), signal.SIGTERM)


def main(arguments=None):
    global FORTI_PATH
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("action", choices=("status", "prepare", "enable", "recover", "diagnose", "health", "import-profile"))
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--forti-path", type=Path)
    args = parser.parse_args(arguments)
    FORTI_PATH = args.forti_path
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, app.terminated)
    try:
        configure(args.data_root)
        if args.action == "status":
            print(json.dumps(state(), ensure_ascii=False))
            return 0
        if args.action == "import-profile":
            if not args.profile:
                raise ValueError("Выберите JSON-профиль.")
            if app.request_control("status") or service_client.status().get("busy"):
                raise ValueError("Сначала завершите активный сеанс разделения.")
            value = profile_store.read(args.profile)
            profile_store.save(app.CONFIG, value)
            app.private_json(app.PREPARED, {"ready": False})
            print("Профиль импортирован. Обновите подготовку без VPN. Адреса не публикуются.", flush=True)
            return 0
        if args.action == "diagnose":
            return app.connection_check()
        if args.action == "prepare":
            service = service_client.status()
            service["current"] = service.get("digest") == service_paths.digest(app.ROOT)
            if not helper_healthy(service):
                raise ValueError("Сначала проверьте системный доступ на этапе настройки.")
            if service.get("installed") and app.recover(service=True) != 0:
                return 3
            return app.prepare()
        # Installation can have succeeded while launchd is still starting. Do
        # not mistake socket startup latency for a rejected system password.
        service = (service_client.wait_current(service_paths.digest(app.ROOT))
                   if args.action == "health" else service_client.status())
        if args.action == "recover" and service.get("installed"):
            return app.recover(service=True)
        if not service.get("installed") or service.get("digest") != service_paths.digest(app.ROOT):
            print("Сначала установите/обновите системный помощник в приложении.", flush=True)
            return 2
        if args.action == "health":
            folder, data = app.new_report("desktop-helper-health")
            data["network_changes"] = False
            guardian = None
            try:
                profile_store.save(health_path(), {"ok": False})
                for scenario in ("release", "parent_eof", "deadline"):
                    guardian = service_client.ServiceGuardian(None, data["guardian_events"], "health")
                    guardian.ready()
                    if scenario == "deadline":
                        while guardian.read_event(8).get("event") != "health_complete":
                            pass
                    final = guardian.release(send=scenario == "release")
                    guardian = None
                    if not final or not final.get("ok") or final.get("reason") != scenario:
                        raise ValueError("Проверка помощника не прошла: " + scenario)
                data["status"] = "helper_health_passed_no_network_changes"
                profile_store.save(health_path(), {"ok": True, "digest": service["digest"]})
                print("Помощник проверен: root, обычный откат канала, EOF и независимый таймер. Маршруты не менялись.", flush=True)
                return 0
            finally:
                if guardian:
                    guardian.release()
                if data["status"] == "started":
                    data["status"] = "helper_health_failed"
                data["finished_at"] = diag.now()
                app.report(data, folder)
        if app.request_control("status"):
            print("Другой сеанс уже работает. Сначала завершите его.", flush=True)
            return 2
        service["current"] = True
        if not helper_healthy(service):
            raise ValueError("Сначала выполните проверку системного доступа.")
        thread = threading.Thread(target=watch_gui, daemon=True)
        thread.start()
        return app.session(gui=True)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if args.action == "status":
            print(json.dumps({"status_error": str(exc)}, ensure_ascii=False), flush=True)
        else:
            print(probe.launch_output(str(exc)), flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
