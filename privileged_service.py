#!/usr/bin/python3
"""Optional launchd service. Narrow route protocol; no shell or arbitrary paths."""
import argparse
import json
import os
import select
import signal
import socket
import stat
import subprocess
import threading
import time
import json_codec

import service_paths as paths
import split_tunnel_helper as helper


class Server:
    def __init__(self, uid, directory):
        self.uid = uid
        self.directory = directory
        self.bundle_hash = paths.digest(directory)
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.busy = False
        self.connections = set()
        self.threads = []
        self.slots = threading.BoundedSemaphore(12)

    def validate_request(self, value):
        if not isinstance(value, dict) or set(value) - {"mode", "spec"}:
            raise ValueError("Unknown request fields")
        mode = value.get("mode")
        if mode not in ("status", "health", "lease", "recover"):
            raise ValueError("Unsupported operation")
        if mode == "lease":
            spec = value.get("spec", {})
            if not isinstance(spec, dict) or set(spec) != {"kind", "seconds", "source", "gateway", "interface", "vpn_interface", "server", "work_addresses"}:
                raise ValueError("Unknown/missing route parameters")
            helper.validate(spec)
        elif value.get("spec") is not None:
            raise ValueError("Unexpected parameters")
        return mode

    def handle(self, conn):
        process = None
        owns_busy = False
        with self.lock:
            self.connections.add(conn)
        try:
            if paths.peer_uid(conn) != self.uid:
                raise PermissionError("Peer UID not allowed")
            conn.settimeout(5)
            buffer = b""
            handshake_deadline = time.monotonic() + 5
            while b"\n" not in buffer and len(buffer) <= 32768:
                remaining = handshake_deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Handshake deadline exceeded")
                conn.settimeout(remaining)
                part = conn.recv(4096)
                if not part:
                    return
                buffer += part
            if len(buffer) > 32768 or b"\n" not in buffer:
                raise ValueError("Invalid request size/framing")
            line, _, trailing = buffer.partition(b"\n")
            if trailing not in (b"", b"release\n"):
                raise ValueError("Unexpected data after handshake")
            value = json_codec.loads(line)
            mode = self.validate_request(value)
            if mode == "status":
                conn.sendall((json.dumps({"api": paths.API_VERSION, "uid": self.uid,
                                          "digest": self.bundle_hash, "busy": self.busy}) + "\n").encode())
                return
            if mode in ("lease", "recover"):
                with self.lock:
                    if self.busy:
                        raise ValueError("A route session/recovery is already running")
                    self.busy = owns_busy = True
            process = subprocess.Popen(paths.worker_argv(self.directory, mode), stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
                                       start_new_session=True,
                                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
                                            "SUDO_UID": str(self.uid), "PYTHONDONTWRITEBYTECODE": "1"})
            if mode == "lease":
                process.stdin.write((json.dumps(value["spec"]) + "\n").encode())
            if trailing:
                process.stdin.write(b"release\n")
                process.stdin.close()
            conn.settimeout(5)
            self.relay(conn, process)
        except Exception as exc:
            try:
                conn.sendall((json.dumps({"event": "error", "message": str(exc)}) + "\n").encode())
            except OSError:
                pass
        finally:
            if process:
                if not process.stdin.closed:
                    process.stdin.close()  # Root guardian sees EOF and performs rollback.
                process.stdin = None
                try:
                    # Drain stdout while waiting: a large rollback receipt must not
                    # block the worker on a full pipe after a GUI crash.
                    process.communicate(timeout=45)
                except (ValueError, subprocess.TimeoutExpired):
                    # Never clear the busy flag while an independent rollback
                    # worker is still alive; nor kill it to make the UI look ready.
                    if owns_busy and process.poll() is None:
                        owns_busy = False
                        thread = threading.Thread(target=self.reap_busy, args=(process,), daemon=True)
                        thread.start()
                try:
                    conn.sendall((json.dumps({"event": "service_exit", "exit_code": process.poll()}) + "\n").encode())
                except OSError:
                    pass
            if owns_busy:
                with self.lock:
                    self.busy = False
            with self.lock:
                self.connections.discard(conn)
            conn.close()

    def reap_busy(self, process):
        try:
            try:
                process.communicate()  # Drain rollback receipts without blocking the server.
            except (OSError, ValueError):
                process.wait()  # Closed pipes must not advertise a live worker as idle.
        finally:
            if process.poll() is not None:
                with self.lock:
                    self.busy = False

    def relay(self, conn, process):
        can_read = True
        while True:
            readers = [process.stdout] + ([conn] if can_read else [])
            ready, _, _ = select.select(readers, [], [], 1)
            if self.stopping.is_set() and not process.stdin.closed:
                process.stdin.close()
            if conn in ready:
                value = conn.recv(128)
                can_read = False  # A release is the ONLY post-handshake operation.
                if not process.stdin.closed:
                    if value:
                        process.stdin.write(b"release\n")
                    process.stdin.close()
            if process.stdout in ready:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    process.wait(timeout=5)
                    return
                conn.sendall(chunk)

    def run(self):
        directory = paths.socket_directory(self.uid)
        directory.mkdir(mode=0o711, exist_ok=True)
        paths.check_root_directory(directory)
        target = paths.socket_path(self.uid)
        if target.exists():
            info = target.lstat()
            if not stat.S_ISSOCK(info.st_mode):
                raise PermissionError("Refusing to replace a non-socket")
            target.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(target))
        os.chmod(target, 0o600)
        os.chown(target, self.uid, -1)
        server.listen(8)
        try:
            while not self.stopping.is_set():
                if not select.select([server], [], [], 0.5)[0]:
                    continue
                conn, _ = server.accept()
                if not self.slots.acquire(blocking=False):
                    conn.close()
                    continue
                def task(client=conn):
                    try:
                        self.handle(client)
                    finally:
                        self.slots.release()
                thread = threading.Thread(target=task, daemon=True)
                self.threads.append(thread)
                thread.start()
                self.threads = [item for item in self.threads if item.is_alive()]
        finally:
            self.stopping.set()
            for thread in self.threads:
                thread.join(2)
            server.close()
            target.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", required=True, type=int)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid < 500:
        raise PermissionError("Service requires root and an explicit local user")
    directory = paths.install_path(args.uid)
    paths.check_root_directory(directory)
    service = Server(args.uid, directory)
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, lambda *_: service.stopping.set())
    service.run()


if __name__ == "__main__":
    main()
