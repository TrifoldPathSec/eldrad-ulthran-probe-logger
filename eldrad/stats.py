"""Summary statistics over stored probe records."""
from __future__ import annotations

from collections import Counter, defaultdict


def summarize(rows: list[dict], top: int = 10) -> dict:
    devices: dict[str, dict] = {}
    for r in rows:
        d = devices.setdefault(r["device"], {"randomized": bool(r["randomized"]), "ssids": set()})
        if r["ssid"]:
            d["ssids"].add(r["ssid"])

    randomized = [d for d in devices.values() if d["randomized"]]
    ssid_devices = Counter(s for d in devices.values() for s in d["ssids"])
    sessions: dict[str, dict] = defaultdict(lambda: {"frames": 0, "devices": set()})
    for r in rows:
        sessions[r["label"]]["frames"] += 1
        sessions[r["label"]]["devices"].add(r["device"])

    n = len(devices) or 1
    return {
        "frames": len(rows),
        "unique_macs": len(devices),
        "randomized_share": len(randomized) / n,
        "broadcast_frame_share": sum(1 for r in rows if not r["ssid"]) / (len(rows) or 1),
        "macs_leaking_ssids": sum(1 for d in devices.values() if d["ssids"]),
        "randomized_leaking_ssids": sum(1 for d in randomized if d["ssids"]),
        "global_leaking_ssids": sum(1 for d in devices.values() if d["ssids"] and not d["randomized"]),
        "unique_ssids": len(ssid_devices),
        "top_ssids": ssid_devices.most_common(top),
        "channels": sorted(Counter(r["channel"] for r in rows if r["channel"]).items()),
        "sessions": {k: {"frames": v["frames"], "unique_macs": len(v["devices"])}
                     for k, v in sessions.items()},
    }


def format_text(s: dict) -> str:
    lines = [
        f"frames                {s['frames']}",
        f"unique MACs           {s['unique_macs']}  (randomization inflates this; it is not a device count)",
        f"randomized MACs       {s['randomized_share']:.0%}",
        f"broadcast probes      {s['broadcast_frame_share']:.0%} of frames",
        f"MACs leaking SSIDs    {s['macs_leaking_ssids']}  "
        f"({s['global_leaking_ssids']} global, {s['randomized_leaking_ssids']} randomized)",
        f"unique SSIDs          {s['unique_ssids']}",
        "",
        "top SSIDs (by MACs probing for them):",
    ]
    lines += [f"  {count:4d}  {ssid}" for ssid, count in s["top_ssids"]]
    lines += ["", "sessions:"]
    lines += [f"  {label}: {v['frames']} frames, {v['unique_macs']} MACs" for label, v in s["sessions"].items()]
    lines += ["", "channels: " + ", ".join(f"{ch}:{n}" for ch, n in s["channels"])]
    return "\n".join(lines)
