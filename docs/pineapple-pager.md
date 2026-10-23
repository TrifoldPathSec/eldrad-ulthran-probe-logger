# Capturing with a WiFi Pineapple Pager

The Pager records the frames and `eldrad ingest` does the analysis on your laptop. The Pager only listens.

> **Status:** these steps use standard OpenWrt tools (`iw`, `tcpdump`, `scp`). They haven't been run on a Pager yet. Interface names and the loot path can differ between firmware versions, so check them on your device first.

## 0. Keep it passive

The Pager can do more than listen. For this project, leave every active feature **off**: PineAP / Evil-Twin / Karma-style SSID impersonation, deauthentication, beacon spoofing, and client association. A probe-request survey doesn't need any of them, and using them on networks you don't own is illegal in most places.

## 1. Find the monitor interface

Connect to the Pager (USB-C ethernet or its management AP) and SSH in:

```sh
ssh root@172.16.42.1        # default Hak5 management address; yours may differ
iw dev                      # look for an interface with "type monitor" (e.g. wlan1mon)
```

If no monitor interface exists, create one on a radio the Pager isn't using for management:

```sh
iw dev wlan1 interface add wlan1mon type monitor
ip link set wlan1mon up
```

## 2. Record only probe requests

```sh
which tcpdump || { opkg update && opkg install tcpdump; }
mkdir -p /root/loot/eldrad
tcpdump -i wlan1mon -s 0 -w /root/loot/eldrad/probes-$(date +%Y%m%d-%H%M).pcap \
        'type mgt subtype probe-req'
```

The BPF filter drops everything except probe requests at capture time, so data frames and other traffic never reach the file.

**Channel hopping:** if the Pager's recon engine is already hopping that radio, leave it alone. Otherwise, run a simple hopper in a second shell:

```sh
while true; do for c in 1 6 11 2 7 3 8 4 9 5 10; do iw dev wlan1mon set channel $c; sleep 0.5; done; done
```

`eldrad` reads each frame's channel from its RadioTap header, so hopping doesn't need any other bookkeeping.

## 3. Note where you were

The Pager has no GPS. Write down a lat/lon for each capture (from your phone's map app). That becomes the session's fixed location.

## 4. Copy back and ingest

```sh
scp root@172.16.42.1:/root/loot/eldrad/probes-*.pcap captures/
.venv/bin/python -m eldrad ingest captures/probes-20261022-1430.pcap \
    --label "Coffee shop" --lat 45.5231 --lon -122.6765
.venv/bin/python -m eldrad map --out captures/map.html
```

For several captures, write a `sessions.json` like [`samples/sessions.json`](../samples/sessions.json) (leave out `salt_hex` so each session gets a random salt) and run `ingest --manifest`.

## 5. Clean up

The pcap on the Pager and in `captures/` holds **real MACs**. The database only holds salted tokens. Once ingested, delete the pcaps from both places unless you have a reason to keep them.
