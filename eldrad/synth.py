"""Synthetic probe-request pcaps for demos, tests and screenshots.

No real device is involved. Global MACs come from 00:00:5E:00:53:00-FF, the
IANA range reserved for documentation (RFC 7042). Randomized MACs are random
bytes with the locally administered bit set. Every SSID is made up. Each pcap
goes through the same ingest path as a real capture.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap
from scapy.utils import wrpcap

SESSIONS = [
    {"label": "Transit hub", "lat": 45.52890, "lon": -122.67680, "minutes": 25, "devices": 70},
    {"label": "Public square", "lat": 45.51890, "lon": -122.67930, "minutes": 30, "devices": 85},
    {"label": "Waterfront market", "lat": 45.52250, "lon": -122.67050, "minutes": 20, "devices": 50},
    {"label": "Campus park blocks", "lat": 45.51150, "lon": -122.68350, "minutes": 20, "devices": 40},
]

# Fictional networks. Weight = how many people have it in their saved-networks list.
COMMON_SSIDS = {
    "CityLibrary-Public": 9, "MetroTransit-Free": 8, "Starlite_Cafe_Guest": 7,
    "Harborview-Hotel-Guest": 5, "Gridline-Hotspot": 5, "Airport-Free-WiFi": 6,
    "CampusNet": 6, "CampusNet-Guest": 3, "OakStreet-Gym": 3, "Riverside_Clinic_Guest": 2,
    "Lumen-Coworking": 3, "Conference-2026": 2,
}
PERSONAS = {"modern": 0.66, "legacy": 0.22, "iot": 0.12}
RSSI_AT_1M, PATH_LOSS_EXPONENT = -40, 2.7
CHANNELS_24 = [1, 6, 11, 1, 6, 11, 3, 9]
CHANNELS_5 = [36, 44, 149]
START = datetime(2026, 10, 18, 15, 0, tzinfo=timezone.utc).timestamp()


class _Macs:
    def __init__(self, rng: random.Random):
        self.rng, self.next_global = rng, 0

    def global_mac(self) -> str:
        n, self.next_global = self.next_global % 256, self.next_global + 1
        return f"00:00:5e:00:53:{n:02x}"

    def randomized(self) -> str:
        first = (self.rng.randrange(256) & 0xFC) | 0x02  # unicast, locally administered
        return ":".join(f"{b:02x}" for b in [first] + [self.rng.randrange(256) for _ in range(5)])


def _home_ssid(rng: random.Random) -> str:
    return rng.choice(["HOME-{:04X}", "Fam_Network_{:d}", "Router-5G-{:04X}", "Apt{:d}-WiFi",
                       "Hearth-{:04X}"]).format(rng.randrange(1, 0xFFFF))


def _pnl(rng: random.Random, k: int) -> list[str]:
    names = list(COMMON_SSIDS)
    picks = set()
    while len(picks) < k - 1:
        picks.add(rng.choices(names, weights=list(COMMON_SSIDS.values()))[0])
    return [_home_ssid(rng)] + sorted(picks)


def _frame(mac: str, ssid: str, rssi: int, channel: int, ts: float):
    freq = 2407 + 5 * channel if channel <= 13 else 5000 + 5 * channel
    flags = 0x00A0 if channel <= 13 else 0x0140  # 2GHz+CCK / 5GHz+OFDM
    pkt = (RadioTap(present="Flags+Channel+dBm_AntSignal", Flags=0, ChannelFrequency=freq,
                    ChannelFlags=flags, dBm_AntSignal=rssi)
           / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3="ff:ff:ff:ff:ff:ff")
           / Dot11ProbeReq()
           / Dot11Elt(ID=0, info=ssid.encode())
           / Dot11Elt(ID=1, info=b"\x02\x04\x0b\x16\x0c\x12\x18\x24")
           / Dot11Elt(ID=3, info=bytes([channel])))
    pkt.time = ts
    return pkt


def _device_frames(rng: random.Random, macs: _Macs, t0: float, minutes: int) -> list:
    persona = rng.choices(list(PERSONAS), weights=list(PERSONAS.values()))[0]
    dist = rng.uniform(2, 120)
    base_rssi = RSSI_AT_1M - 10 * PATH_LOSS_EXPONENT * math.log10(dist)
    arrival = t0 + rng.uniform(0, minutes * 60 * 0.85)
    dual_band = persona != "iot" and rng.random() < 0.7

    if persona == "modern":
        hidden = _home_ssid(rng) if rng.random() < 0.12 else None  # a hidden network forces a directed probe
        bursts, mac, pnl = rng.randint(1, 5), None, []
    elif persona == "legacy":
        bursts, mac, pnl = rng.randint(2, 6), macs.global_mac(), _pnl(rng, rng.randint(2, 7))
    else:
        bursts, mac, pnl = rng.randint(4, 10), macs.global_mac(), [_home_ssid(rng)]

    frames, t = [], arrival
    for _ in range(bursts):
        if persona == "modern":
            mac = macs.randomized()  # new address for each scan
            ssids = [""] + ([hidden] if hidden else [])
        elif persona == "legacy":
            ssids = [""] + pnl
        else:
            ssids = pnl
        for ssid in ssids:
            for _ in range(rng.randint(1, 2)):
                ch = rng.choice(CHANNELS_5 if dual_band and rng.random() < 0.3 else CHANNELS_24)
                rssi = int(max(min(base_rssi + rng.gauss(0, 3), -25), -95))
                frames.append(_frame(mac, ssid, rssi, ch, t + rng.uniform(0, 0.4)))
        t += rng.uniform(15, 90)
    return frames


def generate(out_dir: str | Path, seed: int = 40_000) -> Path:
    """Write one pcap per synthetic session plus a sessions.json manifest for ingest."""
    out = Path(out_dir)
    (out / "pcap").mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    macs = _Macs(rng)
    manifest = []
    for i, s in enumerate(SESSIONS):
        t0 = START + i * 5400
        frames = [f for _ in range(s["devices"]) for f in _device_frames(rng, macs, t0, s["minutes"])]
        frames.sort(key=lambda p: p.time)
        name = f"session{i + 1}.pcap"
        wrpcap(str(out / "pcap" / name), frames)
        manifest.append({
            "label": s["label"], "lat": s["lat"], "lon": s["lon"], "pcap": f"pcap/{name}",
            # Fixed per-session salt so the sample build is reproducible. Real sessions use a random one.
            "salt_hex": hashlib.sha256(f"{seed}:{s['label']}".encode()).hexdigest()[:32],
        })
    path = out / "sessions.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path
