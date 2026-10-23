# Capturing with a WiFi Pineapple Pager

The Pager records the frames and `eldrad ingest` does the analysis on your laptop. The Pager only listens.

> **Status:** tested on 2026-10-22 on a Pager running firmware **24.10.1** (OpenWrt 24.10, `ramips/mt76x8`, mipsel). A 5-minute capture gave 334 probe requests, all with RSSI and channel, parsed with no errors. Other firmware versions may name things differently, so check step 2's output on yours.

## 1. Connect over USB-C, not WiFi

Joining the Pager's management WiFi drops your laptop's internet. Use the cable instead: the Pager shows up on the Mac as a **USB 10/100/1000 LAN** interface (MAC prefix `00:13:37`, Hak5), hands out a `172.16.52.x` address, and sits at **`172.16.52.1`**. Your WiFi stays connected.

If web pages stall while the Pager is plugged in, it's because the Pager also advertises a default route. Fix it in **System Settings → Network → … → Set Service Order** by dragging Wi-Fi above the USB LAN.

Optional: key-based SSH, so scripts can connect without a password prompt:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pager_ed25519 -N "" -C "eldrad-pager-lab"
ssh root@172.16.52.1 'mkdir -p /root/.ssh /etc/dropbear; cat >> /root/.ssh/authorized_keys; cp /root/.ssh/authorized_keys /etc/dropbear/authorized_keys 2>/dev/null; chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys /etc/dropbear/authorized_keys' < ~/.ssh/pager_ed25519.pub
alias pager='ssh -i ~/.ssh/pager_ed25519 root@172.16.52.1'
```

## 2. Look before you capture

```sh
cat /etc/openwrt_release        # firmware
iw dev                          # monitor interfaces
which tcpdump                   # preinstalled on 24.10.1
df -h /mmc                      # microSD storage, use it for pcaps
```

On the tested unit, two monitor interfaces already existed, so none needed creating:

| Interface | Radio | Behaviour under pineapd |
|---|---|---|
| `wlan0mon` | phy0 | fixed on channel 1 |
| `wlan1mon` | phy1 | hops 2.4 / 5 / 6 GHz quickly (pineapd recon) |

## 3. Make it passive: turn PineAP off

**Check this every time.** On the tested unit, PineAP was **enabled**. It was broadcasting beacons from an SSID pool that `autossidpool` had filled automatically with network names harvested from nearby devices' probe requests. That's active impersonation, and the harvested pool is bystander data. Check and fix it:

```sh
uci -q get pineapd.@hostapd[0].pineap_disabled      # want 1
uci -q get pineapd.@pineapd[0].autossidpool         # want 0
uci -q get pineapd.@ssidpool[0].ssid | wc -w        # harvested pool size, want 0

uci set pineapd.@hostapd[0].pineap_disabled=1
uci set pineapd.@pineapd[0].autossidpool=0
uci -q delete pineapd.@ssidpool[0].ssid             # clears the harvested pool
uci commit pineapd
/etc/init.d/pineapd restart
iw dev | grep type                                  # only monitor + managed, no AP
```

pineapd's recon mode is passive: it listens, hops `wlan1mon`, and logs APs and handshakes to `/root/loot`. It stays on to do the channel hopping. Leave deauth and other attack payloads alone.

## 4. Record only probe requests

```sh
mkdir -p /mmc/eldrad; T=$(date +%Y%m%d-%H%M)
for i in wlan0mon wlan1mon; do
  tcpdump -i $i -s 0 -G 300 -W 1 -w /mmc/eldrad/probes-$i-$T.pcap 'type mgt subtype probe-req' &
done; wait
```

- The BPF filter drops everything except probe requests at capture time.
- `-G 300 -W 1` stops after 5 minutes, at the first packet after the mark.
- Expect `wlan0mon` (parked on channel 1) to collect far more than the hopping `wlan1mon`. In the test it was 316 frames vs 18, because most clients probe on 2.4 GHz and the hopper spends only a moment on each channel.
- `eldrad` reads each frame's channel from RadioTap, so no hop bookkeeping is needed.

## 5. Note where you were

The Pager's gpsd config exists, but without a GPS attached, write down a lat/lon from your phone for each capture. That becomes the session's fixed location.

## 6. Copy back and ingest

```bash
scp -O -i ~/.ssh/pager_ed25519 'root@172.16.52.1:/mmc/eldrad/*.pcap' captures/
.venv/bin/python -m eldrad ingest captures/probes-wlan0mon-*.pcap --label "Coffee shop ch1" --lat 45.5231 --lon -122.6765
.venv/bin/python -m eldrad ingest captures/probes-wlan1mon-*.pcap --label "Coffee shop hop" --lat 45.5231 --lon -122.6765
.venv/bin/python -m eldrad stats
.venv/bin/python -m eldrad map --out captures/map.html
```

`-O` makes `scp` use the classic SCP protocol, which worked against the Pager's SSH server. `captures/` is git-ignored.

## 7. Clean up

The pcaps on the Pager and in `captures/` hold **real MACs and SSIDs**. The database only holds salted tokens (SSIDs are kept as heard). Once ingested:

```sh
rm /mmc/eldrad/*.pcap            # on the Pager
```

```bash
rm captures/probes-*.pcap        # on the laptop
```
