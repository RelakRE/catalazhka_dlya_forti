"""Portable platform boundary. Windows is an explicit non-operational future port."""
from dataclasses import asdict, dataclass
import platform
from typing import Protocol, Sequence


@dataclass(frozen=True)
class PlatformInfo:
    system: str
    architecture: str
    supported: bool
    reason: str
    route_engine: str
    privileged_transport: str
    contract_version: int = 1

    def json(self):
        return asdict(self)


class DesktopBackend(Protocol):
    """Implement per-OS preflight/dispatch; privileged route ownership stays OS-specific."""
    def run(self, arguments: Sequence[str]) -> int:
        ...


def describe(system=None, architecture=None, version=None):
    system = platform.system() if system is None else system
    architecture = platform.machine() if architecture is None else architecture
    if system == "Windows":
        return PlatformInfo(system, architecture, False, "Windows-порт пока не реализован. Сетевые команды не выполняются.",
                            "planned: IP Helper API", "planned: authenticated local named pipe")
    if system != "Darwin":
        return PlatformInfo(system, architecture, False, "Поддерживается только macOS Intel. Эта платформа пока не реализована.", "none", "none")
    if architecture != "x86_64":
        return PlatformInfo(system, architecture, False, "Этот выпуск только для Intel Mac; Apple Silicon не поддерживается.", "none", "none")
    version = platform.mac_ver()[0] if version is None else version
    try:
        major = int(version.split(".")[0])
    except (TypeError, ValueError):
        major = 0
    supported = major >= 13
    return PlatformInfo(system, architecture, supported, "" if supported else "Для этого выпуска нужна macOS 13 или новее.",
                        "macOS IPv4 route guardian", "Unix socket + getpeereid")
