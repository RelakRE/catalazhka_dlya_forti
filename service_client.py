"""Unprivileged client for the optional installed routing helper."""
import json
import os
import select
import socket
import time
import re
import json_codec
from types import SimpleNamespace

import route_probe_helper as base
import service_paths as paths


def connect():
    paths.check_root_directory(paths.socket_directory(os.getuid()))
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(4)
        conn.connect(str(paths.socket_path(os.getuid())))
        if paths.peer_uid(conn) != 0:
            raise PermissionError("The routing helper is not root")
        return conn
    except Exception:
        conn.close()
        raise


def status():
    try:
        conn = connect()
        with conn:
            conn.sendall(b'{"mode":"status"}\n')
            raw = b""
            while b"\n" not in raw and len(raw) < 4096:
                part = conn.recv(4096)
                if not part:
                    break
                raw += part
            result = json_codec.loads(raw)
            if (not isinstance(result, dict) or set(result) != {"api", "uid", "digest", "busy"}
                    or type(result["api"]) is not int or result["api"] != paths.API_VERSION
                    or type(result["uid"]) is not int or result["uid"] != os.getuid()
                    or type(result["busy"]) is not bool
                    or not isinstance(result["digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", result["digest"])):
                raise ValueError("Unexpected helper protocol/user")
            return {"installed": True, **result}
    except (OSError, ValueError) as exc:
        return {"installed": False, "message": str(exc)}


class ServiceGuardian:
    def __init__(self, spec, events, mode="lease"):
        self.conn = connect()
        self.events = events
        self.buffer = b""
        self.mode = mode
        self.started = False
        self.process = SimpleNamespace(stdout=self.conn, returncode=None)
        request = {"mode": mode}
        if spec is not None:
            request["spec"] = spec
        self.conn.sendall((json.dumps(request) + "\n").encode())

    def read_event(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                try:
                    event = json_codec.loads(raw)
                    if not isinstance(event, dict) or not isinstance(event.get("event"), str):
                        raise ValueError("Invalid event shape")
                except ValueError:
                    event = {"event": "error", "message": "Invalid helper response"}
                self.events.append(event)
                if event.get("event") == "service_exit":
                    self.process.returncode = event.get("exit_code")
                return event
            if not select.select([self.conn], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            part = self.conn.recv(65536)
            if not part:
                raise base.ProbeError("Канал системного помощника закрыт. Проверьте откат в отчёте.")
            self.buffer += part
            if len(self.buffer) > 1024 * 1024:
                raise base.ProbeError("Слишком большой ответ помощника.")
        raise base.ProbeError("Помощник не ответил вовремя.")

    def ready(self):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            event = self.read_event(max(0.1, deadline - time.monotonic()))
            kind = event.get("event")
            if kind == "hello":
                if event.get("protocol") != base.PROTOCOL_VERSION or event.get("uid") != 0 or event.get("mode") != self.mode:
                    raise base.ProbeError("Неверные права/протокол помощника.")
                self.started = True
            elif kind == "error":
                raise base.ProbeError(event.get("message", "Ошибка помощника"))
            elif kind == "ready":
                if not self.started:
                    raise base.ProbeError("Нет подтверждения прав помощника.")
                return event
        raise base.ProbeError("Помощник не подтвердил начало сеанса.")

    def release(self, send=True):
        final = next((item for item in reversed(self.events) if item.get("event") in
                      ("rolled_back", "rollback_error", "health_complete")), None)
        try:
            if send:
                self.conn.sendall(b"release\n")
            self.conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        deadline = time.monotonic() + 45
        try:
            if self.process.returncode is not None:
                return final
            while time.monotonic() < deadline:
                event = self.read_event(max(0.1, deadline - time.monotonic()))
                if event.get("event") in ("rolled_back", "rollback_error", "health_complete"):
                    final = event
                if event.get("event") == "service_exit":
                    return final
            return final
        finally:
            self.conn.close()
