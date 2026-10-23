"""Parse 802.11 probe request frames (management type 0, subtype 4) into plain records."""
from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap

ELT_SSID = 0
ELT_DS_PARAMS = 3


@dataclass
class Probe:
    ts: float
    mac: str
    ssid: str  # "" is a broadcast (wildcard) probe
    rssi: int | None
    channel: int | None
    randomized: bool


def is_locally_administered(mac: str) -> bool:
    """True when the U/L bit (0x02 of the first octet) is set, as randomized MACs are."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    return bool(int(mac.split(":")[0], 16) & 0x01)


def freq_to_channel(freq: int | None) -> int | None:
    if not freq or freq <= 0:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5150 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    return None


def _elements(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        yield elt
        elt = elt.payload.getlayer(Dot11Elt)


def parse_probe(pkt, fallback_channel: int | None = None) -> Probe | None:
    """Return a Probe for a probe request frame, or None for anything else."""
    if not pkt.haslayer(Dot11ProbeReq):
        return None
    dot11 = pkt.getlayer(Dot11)  # also matches Dot11FCS
    if dot11 is None or dot11.type != 0 or dot11.subtype != 4:
        return None
    mac = (dot11.addr2 or "").lower()
    if len(mac) != 17 or is_multicast(mac):
        return None

    ssid, ds_channel = "", None
    for elt in _elements(pkt):
        info = bytes(elt.info or b"")
        if elt.ID == ELT_SSID and not ssid:
            ssid = "" if not info.strip(b"\x00") else info.decode("utf-8", errors="replace")
        elif elt.ID == ELT_DS_PARAMS and info:
            ds_channel = info[0]

    rssi, channel = None, None
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        rssi = getattr(rt, "dBm_AntSignal", None)
        channel = freq_to_channel(getattr(rt, "ChannelFrequency", None))

    return Probe(
        ts=float(pkt.time),
        mac=mac,
        ssid=ssid,
        rssi=int(rssi) if rssi is not None else None,
        channel=channel or ds_channel or fallback_channel,
        randomized=is_locally_administered(mac),
    )
