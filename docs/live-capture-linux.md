# Live capture on Linux (Raspberry Pi or Kali)

> **Status:** written for Linux but not yet run on hardware. Offline ingest (see [pineapple-pager.md](pineapple-pager.md)) is the tested path.

## Hardware

Any Linux host with a USB WiFi adapter that supports monitor mode in-kernel. Good choices:

| Adapter | Chipset | Driver | Bands |
|---|---|---|---|
| Alfa AWUS036ACM | MT7612U | `mt76x2u` | 2.4 + 5 GHz |
| Alfa AWUS036ACHM | MT7610U | `mt76x0u` | 2.4 + 5 GHz |
| Alfa AWUS036NHA | AR9271 | `ath9k_htc` | 2.4 GHz |
| Generic RT5370 dongle | RT5370 | `rt2800usb` | 2.4 GHz |

The Pi's built-in WiFi (Broadcom/Cypress) doesn't support monitor mode without nexmon patches, so use a USB adapter. A Pi 4 or 5 can power a dual-band Alfa directly. A Pi Zero 2 W needs a powered hub.

Apple Silicon Macs can't boot a Kali USB, and macOS can't hand a USB WiFi adapter to Scapy in monitor mode. On a Mac, use offline ingest instead.

## Setup

```bash
sudo apt install -y python3-venv iw tcpdump
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
iw dev                                      # find the adapter, e.g. wlan1
sudo .venv/bin/python -m eldrad monitor up wlan1 --dry-run   # show the commands
sudo .venv/bin/python -m eldrad monitor up wlan1
sudo .venv/bin/python -m eldrad monitor status wlan1         # expect "type monitor"
```

`monitor up` releases the interface from NetworkManager (`nmcli device set wlan1 managed no`), brings it down, sets `type monitor`, and brings it back up. If something still grabs it, `sudo airmon-ng check kill` is the blunt fix on Kali.

## Capture

```bash
# fixed location, 2.4 GHz channels 1-11, 0.5 s dwell
sudo .venv/bin/python -m eldrad capture --iface wlan1 --label "Bench test" --lat 45.5231 --lon -122.6765

# dual-band adapter, 10 minutes
sudo .venv/bin/python -m eldrad capture --iface wlan1 --channels 1,6,11,36,44,149 --duration 600 --lat ... --lon ...
```

The channel hopper drops any channel the driver rejects, which is common for 5 GHz DFS channels under some regulatory domains (`iw reg get`). Each frame's channel is read from RadioTap. The hopper's current channel is only a fallback.

## GPS (optional)

```bash
sudo apt install -y gpsd gpsd-clients
sudo gpsd /dev/ttyACM0 -F /var/run/gpsd.sock     # u-blox 7 / VK-162 style puck
cgps -s                                          # wait for a 2D/3D fix
sudo .venv/bin/python -m eldrad capture --iface wlan1 --gpsd --lat 45.5231 --lon -122.6765
```

With `--gpsd`, each frame is tagged with the latest TPV fix from gpsd on `127.0.0.1:2947`. Until the first fix arrives, or if gpsd drops out, the `--lat/--lon` fallback is used. The client is a small JSON reader, so no gps Python package is needed.

## Tear down

```bash
sudo .venv/bin/python -m eldrad monitor down wlan1
```
