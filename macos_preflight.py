"""Read-only prerequisites, separated from portable models and privileged actions."""
import os
from pathlib import Path

from platform_contract import describe


def snapshot(forti_path=None):
    candidates = [Path(forti_path)] if forti_path else [Path("/Applications/FortiClient.app"), Path.home() / "Applications/FortiClient.app"]
    found = any(path.is_dir() and (path / "Contents/Info.plist").is_file() for path in candidates)
    return {"platform": describe().json(), "forticlient_available": found,
            "current_user": os.getuid(), "admin_required_once": True,
            "supported_vpn": "FortiClient SSL / utun / IPv4", "supported_interfaces": "enN (Wi-Fi/Ethernet)",
            "dns_split": False, "ipv6_split": False}
