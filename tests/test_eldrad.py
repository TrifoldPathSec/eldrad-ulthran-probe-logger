import tempfile
import unittest
from pathlib import Path

from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, Dot11FCS, Dot11ProbeReq, RadioTap)
from scapy.packet import raw

from eldrad.capture import Recorder, ingest_pcap
from eldrad.frames import freq_to_channel, is_locally_administered, parse_probe
from eldrad.location import FixedLocation
from eldrad.mapgen import build_map
from eldrad.privacy import MacAnonymizer
from eldrad.stats import summarize
from eldrad.store import ProbeStore
from eldrad.synth import generate

BCAST = "ff:ff:ff:ff:ff:ff"


def probe(mac="00:00:5e:00:53:01", ssid=b"CityLibrary-Public", rssi=-60, freq=2437, fcs=False):
    rt = RadioTap(present="Flags+Channel+dBm_AntSignal", Flags="FCS" if fcs else 0,
                  ChannelFrequency=freq, ChannelFlags=0x80, dBm_AntSignal=rssi)
    dot11 = (Dot11FCS if fcs else Dot11)(type=0, subtype=4, addr1=BCAST, addr2=mac, addr3=BCAST)
    pkt = rt / dot11 / Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid) / Dot11Elt(ID=3, info=b"\x06")
    return RadioTap(raw(pkt))  # round-trip through bytes like a real capture


class FrameTests(unittest.TestCase):
    def test_parses_probe_fields(self):
        p = parse_probe(probe())
        self.assertEqual((p.mac, p.ssid, p.rssi, p.channel, p.randomized),
                         ("00:00:5e:00:53:01", "CityLibrary-Public", -60, 6, False))

    def test_broadcast_probe_has_empty_ssid(self):
        self.assertEqual(parse_probe(probe(ssid=b"")).ssid, "")

    def test_randomized_bit(self):
        self.assertTrue(is_locally_administered("da:a1:19:00:00:01"))
        self.assertFalse(is_locally_administered("00:00:5e:00:53:01"))
        self.assertTrue(parse_probe(probe(mac="06:11:22:33:44:55")).randomized)

    def test_fcs_frames_and_5ghz(self):
        p = parse_probe(probe(fcs=True, freq=5180))
        self.assertEqual(p.channel, 36)

    def test_ignores_non_probe_frames(self):
        beacon = RadioTap() / Dot11(type=0, subtype=8, addr2="00:00:5e:00:53:02") / Dot11Beacon()
        self.assertIsNone(parse_probe(beacon))

    def test_freq_to_channel(self):
        self.assertEqual([freq_to_channel(f) for f in (2412, 2484, 5745, 5955, 0)], [1, 14, 149, 1, None])


class PrivacyTests(unittest.TestCase):
    def test_token_stable_within_session_and_unlinkable_across(self):
        a, b = MacAnonymizer(), MacAnonymizer()
        mac = "00:00:5e:00:53:01"
        self.assertEqual(a.token(mac), a.token(mac.upper()))
        self.assertNotEqual(a.token(mac), b.token(mac))
        self.assertIsNone(a.raw(mac))
        self.assertEqual(MacAnonymizer(keep_raw=True).raw(mac), mac)

    def test_store_has_no_raw_mac_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            store = ProbeStore(Path(d) / "t.db")
            sid = store.start_session("t", 1.0, 2.0, "test")
            rec = Recorder(store, sid, MacAnonymizer(), FixedLocation(1.0, 2.0))
            rec.handle(probe())
            row = store.rows()[0]
            self.assertIsNone(row["mac_raw"])
            self.assertNotEqual(row["device"], "00:00:5e:00:53:01")
            self.assertEqual(row["oui"], "00:00:5e")


class MapTests(unittest.TestCase):
    def test_ssids_are_html_escaped(self):
        evil = "<img src=x onerror=alert(1)>"
        with tempfile.TemporaryDirectory() as d:
            store = ProbeStore(Path(d) / "t.db")
            sid = store.start_session("t", 45.5, -122.6, "test")
            Recorder(store, sid, MacAnonymizer(), FixedLocation(45.5, -122.6)).handle(probe(ssid=evil.encode()))
            store.commit()
            out = Path(d) / "m.html"
            build_map(store.rows(), str(out))
            html = out.read_text()
            self.assertNotIn(evil, html)
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)


class PipelineTests(unittest.TestCase):
    def test_synthetic_pcaps_ingest(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = generate(d, seed=7)
            store = ProbeStore(Path(d) / "t.db")
            sid = store.start_session("s1", 45.5, -122.6, "test")
            n = ingest_pcap(str(Path(d) / "pcap" / "session1.pcap"),
                            Recorder(store, sid, MacAnonymizer(), FixedLocation(45.5, -122.6)))
            self.assertTrue(manifest.exists())
            self.assertGreater(n, 100)
            s = summarize(store.rows())
            self.assertGreater(s["randomized_share"], 0.5)
            self.assertTrue(all(not r["mac_raw"] for r in store.rows()))


if __name__ == "__main__":
    unittest.main()
