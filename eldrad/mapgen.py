"""Folium map of probe requests: capture locations, RSSI-sized devices, heatmap and stats.

SSIDs are attacker-controlled bytes from the air, so every one is HTML-escaped
before it goes into a popup, tooltip or the stats panel.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter, defaultdict
from html import escape

import folium
from folium.plugins import HeatMap

from .stats import summarize

RANDOMIZED_COLOR = "#2a78d6"
GLOBAL_COLOR = "#d6542a"
LOCATION_COLOR = "#3d3d3d"

# Log-distance path loss, only used to spread device dots around the capture point.
RSSI_AT_1M = -40
PATH_LOSS_EXPONENT = 2.7


def redact(ssid: str) -> str:
    return "ssid-" + hashlib.sha256(ssid.encode()).hexdigest()[:6] if ssid else ""


def rssi_radius(rssi: int | None) -> float:
    """Stronger signal, bigger dot: -95 dBm maps to 4 px, -30 dBm to 16 px."""
    if rssi is None:
        return 4.0
    return 4 + 12 * (min(max(rssi, -95), -30) + 95) / 65


def estimated_distance_m(rssi: int | None) -> float:
    if rssi is None:
        return 60.0
    return min(max(10 ** ((RSSI_AT_1M - rssi) / (10 * PATH_LOSS_EXPONENT)), 1.0), 150.0)


def offset(lat: float, lon: float, device: str, meters: float) -> tuple[float, float]:
    """Deterministic bearing per device so the layout is stable between runs."""
    bearing = int(device[:8], 16) / 0xFFFFFFFF * 2 * math.pi
    dlat = meters * math.cos(bearing) / 111_320
    dlon = meters * math.sin(bearing) / (111_320 * math.cos(math.radians(lat)))
    return lat + dlat, lon + dlon


def _ssid_list(counter: Counter, limit: int = 12) -> str:
    items = "".join(f"<li>{escape(s)} <span style='color:#777'>({n})</span></li>"
                    for s, n in counter.most_common(limit))
    more = f"<li>… {len(counter) - limit} more</li>" if len(counter) > limit else ""
    return f"<ul style='margin:4px 0;padding-left:18px'>{items}{more}</ul>" if items else "<i>broadcast only</i>"


def _stats_panel(s: dict, title: str) -> str:
    top = "".join(f"<tr><td>{escape(ssid)}</td><td style='text-align:right'>{n}</td></tr>"
                  for ssid, n in s["top_ssids"][:8])
    return f"""
    <div style="position:fixed;bottom:24px;left:12px;z-index:9999;max-width:290px;
                background:rgba(255,255,255,.94);color:#222;padding:10px 12px;border-radius:8px;
                font:12px/1.4 -apple-system,Segoe UI,sans-serif;box-shadow:0 1px 6px rgba(0,0,0,.3)">
      <div style="font-weight:600;font-size:13px;margin-bottom:4px">{escape(title)}</div>
      <div>{s['frames']:,} probe frames &middot; {s['unique_macs']} unique MACs</div>
      <div>{s['randomized_share']:.0%} randomized MACs &middot; {s['broadcast_frame_share']:.0%} broadcast probes</div>
      <div>{s['macs_leaking_ssids']} MACs named an SSID ({s['global_leaking_ssids']} global)</div>
      <table style="width:100%;margin-top:6px;border-collapse:collapse">
        <tr><th style="text-align:left">Top SSIDs</th><th style="text-align:right">MACs</th></tr>{top}
      </table>
      <div style="margin-top:6px">
        <span style="color:{RANDOMIZED_COLOR}">&#9679;</span> randomized MAC &nbsp;
        <span style="color:{GLOBAL_COLOR}">&#9679;</span> global MAC<br>
        Dot size = RSSI. Distance from the capture point is a rough path-loss estimate, not a real position.
      </div>
    </div>"""


def build_map(rows: list[dict], out: str, title: str = "eldrad-ulthran probe map",
              redact_ssids: bool = False, zoom: int = 15) -> dict:
    rows = [r for r in rows if r["lat"] is not None and r["lon"] is not None]
    if not rows:
        raise SystemExit("no rows with a location; capture with --lat/--lon or --gpsd")
    if redact_ssids:
        rows = [{**r, "ssid": redact(r["ssid"])} for r in rows]

    center = (sum(r["lat"] for r in rows) / len(rows), sum(r["lon"] for r in rows) / len(rows))
    fmap = folium.Map(location=center, zoom_start=zoom, tiles="OpenStreetMap", control_scale=True)

    # Capture locations: one marker per distinct point, popup lists the SSIDs heard there.
    by_loc: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        by_loc[(round(r["lat"], 5), round(r["lon"], 5))].append(r)
    loc_layer = folium.FeatureGroup(name="Capture locations")
    for (lat, lon), group in by_loc.items():
        devices = {r["device"]: r["randomized"] for r in group}
        pairs = {(r["device"], r["ssid"]) for r in group if r["ssid"]}
        ssid_counts = Counter(s for _, s in pairs)  # MACs per SSID
        labels = ", ".join(sorted({escape(r["label"] or "") for r in group}))
        rand = sum(devices.values()) / len(devices)
        popup = (f"<b>{labels}</b><br>{len(group)} frames &middot; {len(devices)} MACs "
                 f"&middot; {rand:.0%} randomized<br><b>SSIDs probed</b>{_ssid_list(ssid_counts)}")
        folium.Marker((lat, lon), popup=folium.Popup(popup, max_width=320),
                      tooltip=f"{labels}: {len(devices)} MACs",
                      icon=folium.Icon(color="black", icon="signal", prefix="fa")).add_to(loc_layer)
        folium.Circle((lat, lon), radius=150, color=LOCATION_COLOR, weight=1, fill=False,
                      dash_array="4 6").add_to(loc_layer)

    # Devices: anchored at the frame with the strongest RSSI, sized by that RSSI.
    per_device: dict[str, dict] = {}
    for r in rows:
        d = per_device.setdefault(r["device"], {"best": r, "ssids": Counter(), "frames": 0})
        d["frames"] += 1
        if r["ssid"]:
            d["ssids"][r["ssid"]] += 1
        if (r["rssi"] or -999) > (d["best"]["rssi"] or -999):
            d["best"] = r

    dev_layer = folium.FeatureGroup(name="Devices (RSSI-sized)")
    heat = []
    for device, d in per_device.items():
        best = d["best"]
        dist = estimated_distance_m(best["rssi"])
        lat, lon = offset(best["lat"], best["lon"], device, dist)
        color = RANDOMIZED_COLOR if best["randomized"] else GLOBAL_COLOR
        kind = "randomized" if best["randomized"] else "global"
        rssi_txt = f"{best['rssi']} dBm" if best["rssi"] is not None else "no RSSI"
        popup = (f"<b>{device}</b> ({kind} MAC)<br>{d['frames']} frames &middot; best {rssi_txt} "
                 f"&middot; ~{dist:.0f} m<br><b>SSIDs</b>{_ssid_list(d['ssids'])}")
        folium.CircleMarker((lat, lon), radius=rssi_radius(best["rssi"]), color=color, weight=1,
                            fill=True, fill_color=color, fill_opacity=0.55,
                            tooltip=f"{device[:8]}… {kind}, {rssi_txt}",
                            popup=folium.Popup(popup, max_width=300)).add_to(dev_layer)
        heat.append([lat, lon, rssi_radius(best["rssi"]) / 16])

    heat_layer = folium.FeatureGroup(name="Heatmap", show=False)
    HeatMap(heat, radius=18, blur=14, min_opacity=0.3).add_to(heat_layer)

    for layer in (heat_layer, dev_layer, loc_layer):
        layer.add_to(fmap)
    folium.LayerControl(collapsed=False).add_to(fmap)

    summary = summarize(rows)
    fmap.get_root().html.add_child(folium.Element(_stats_panel(summary, title)))
    fmap.get_root().header.add_child(folium.Element(f"<title>{escape(title)}</title>"))
    fmap.save(out)
    return summary
