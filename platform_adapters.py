"""Late-bound adapters: portable entrypoints never import Unix-only code on Windows."""
import json

from platform_contract import DesktopBackend, PlatformInfo
from setup_flow import flow


class MacOSBackend:
    def run(self, arguments):
        from gui_backend import main
        return main(arguments)


class UnavailableBackend:
    def __init__(self, info: PlatformInfo):
        self.info = info

    def run(self, arguments):
        state = {"platform": self.info.json(), "status_error": self.info.reason}
        state["flow"] = flow(state)
        print(json.dumps(state, ensure_ascii=False))
        return 2


def select_backend(info: PlatformInfo) -> DesktopBackend:
    if info.supported and info.system == "Darwin":
        return MacOSBackend()
    return UnavailableBackend(info)
