"""Monitor-mode setup helper for Linux (iw + ip). Receive-only: nothing here transmits."""
from __future__ import annotations

import shutil
import subprocess


def _run(cmd: list[str], dry_run: bool) -> None:
    print("+ " + " ".join(cmd))
    if not dry_run:
        subprocess.run(cmd, check=True)


def _require_tools() -> None:
    missing = [t for t in ("iw", "ip") if shutil.which(t) is None]
    if missing:
        raise SystemExit(f"missing {', '.join(missing)}: this helper needs Linux with iw and iproute2")


def monitor_up(iface: str, dry_run: bool = False) -> None:
    """Put iface into monitor mode. Stop NetworkManager/wpa_supplicant from managing it first."""
    if not dry_run:
        _require_tools()
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "managed", "no"], dry_run)
    _run(["ip", "link", "set", iface, "down"], dry_run)
    _run(["iw", "dev", iface, "set", "type", "monitor"], dry_run)
    _run(["ip", "link", "set", iface, "up"], dry_run)


def monitor_down(iface: str, dry_run: bool = False) -> None:
    """Return iface to managed mode and hand it back to NetworkManager."""
    if not dry_run:
        _require_tools()
    _run(["ip", "link", "set", iface, "down"], dry_run)
    _run(["iw", "dev", iface, "set", "type", "managed"], dry_run)
    _run(["ip", "link", "set", iface, "up"], dry_run)
    if shutil.which("nmcli"):
        _run(["nmcli", "device", "set", iface, "managed", "yes"], dry_run)


def status(iface: str) -> str:
    _require_tools()
    return subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, check=True).stdout


def set_channel(iface: str, channel: int) -> bool:
    result = subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                            capture_output=True, text=True)
    return result.returncode == 0
