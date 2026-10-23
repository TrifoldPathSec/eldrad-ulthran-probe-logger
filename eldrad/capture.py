"""Passive capture: live sniffing with channel hopping, or offline pcap ingest.

Nothing in this module sends frames. There is no injection, deauth or association;
the adapter only listens.
"""
from __future__ import annotations

import itertools
import threading

from scapy.layers.dot11 import Dot11ProbeReq
from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from .frames import parse_probe
from .monitor import set_channel
from .privacy import MacAnonymizer
from .store import ProbeStore

DEFAULT_CHANNELS = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10]


class Recorder:
    """Parses frames and writes probe requests to the store for one session."""

    def __init__(self, store: ProbeStore, session_id: str, anon: MacAnonymizer, location):
        self.store, self.session_id, self.anon, self.location = store, session_id, anon, location
        self.count = 0

    def handle(self, pkt, fallback_channel: int | None = None) -> None:
        probe = parse_probe(pkt, fallback_channel)
        if probe is None:
            return
        lat, lon = self.location.current()
        self.store.add(self.session_id, probe, self.anon, lat, lon)
        self.count += 1
        if self.count % 200 == 0:
            self.store.commit()


class ChannelHopper(threading.Thread):
    """Cycles the monitor interface through channels; drops ones the driver rejects."""

    def __init__(self, iface: str, channels: list[int], dwell: float):
        super().__init__(daemon=True)
        self.iface, self.channels, self.dwell = iface, list(channels), dwell
        self.current: int | None = None
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set() and self.channels:
            for ch in itertools.cycle(list(self.channels)):
                if self._stop.is_set():
                    return
                if set_channel(self.iface, ch):
                    self.current = ch
                    self._stop.wait(self.dwell)
                else:
                    print(f"channel {ch} rejected by {self.iface}, skipping it")
                    self.channels.remove(ch)
                    break

    def stop(self) -> None:
        self._stop.set()


def capture_live(iface: str, recorder: Recorder, channels: list[int] | None = None,
                 dwell: float = 0.5, hop: bool = True, duration: float | None = None) -> int:
    hopper = ChannelHopper(iface, channels or DEFAULT_CHANNELS, dwell) if hop else None
    if hopper:
        hopper.start()
    try:
        sniff(iface=iface, store=False, timeout=duration,
              lfilter=lambda p: p.haslayer(Dot11ProbeReq),
              prn=lambda p: recorder.handle(p, hopper.current if hopper else None))
    finally:
        if hopper:
            hopper.stop()
        recorder.store.commit()
    return recorder.count


def ingest_pcap(path: str, recorder: Recorder) -> int:
    """Read a pcap/pcapng (e.g. from a WiFi Pineapple Pager) and record its probe requests."""
    with PcapReader(path) as reader:
        for pkt in reader:
            recorder.handle(pkt)
    recorder.store.commit()
    return recorder.count
