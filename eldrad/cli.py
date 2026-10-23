"""Command line entry point: python -m eldrad <command>."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_DB = "captures/probes.db"  # captures/ is git-ignored


def _anonymizer(args, salt: bytes | None = None):
    from .privacy import MacAnonymizer, load_or_create_salt
    if args.salt_file:
        salt = load_or_create_salt(args.salt_file)
    if args.store_raw_mac:
        print("WARNING: --store-raw-mac keeps real MAC addresses in the database. "
              "Never publish or share that file.", file=sys.stderr)
    return MacAnonymizer(salt=salt, keep_raw=args.store_raw_mac)


def cmd_monitor(args) -> None:
    from . import monitor
    if args.action == "up":
        monitor.monitor_up(args.iface, args.dry_run)
    elif args.action == "down":
        monitor.monitor_down(args.iface, args.dry_run)
    else:
        print(monitor.status(args.iface))


def cmd_capture(args) -> None:
    from .capture import Recorder, capture_live
    from .location import FixedLocation, GpsdLocation
    from .store import ProbeStore

    fixed = FixedLocation(args.lat, args.lon)
    location = GpsdLocation(fixed) if args.gpsd else fixed
    store = ProbeStore(args.db)
    session = store.start_session(args.label, args.lat, args.lon, f"live:{args.iface}")
    recorder = Recorder(store, session, _anonymizer(args), location)
    channels = [int(c) for c in args.channels.split(",")] if args.channels else None
    print(f"session {session}: listening on {args.iface} (receive only), Ctrl-C to stop")
    try:
        n = capture_live(args.iface, recorder, channels, args.dwell, not args.no_hop, args.duration)
    finally:
        location.stop()
        store.close()
    print(f"recorded {n} probe requests to {args.db}")


def cmd_ingest(args) -> None:
    from .capture import Recorder, ingest_pcap
    from .location import FixedLocation
    from .store import ProbeStore

    if args.manifest:
        base = Path(args.manifest).parent
        jobs = [(base / s["pcap"], s["label"], s["lat"], s["lon"], bytes.fromhex(s["salt_hex"])
                 if s.get("salt_hex") else None) for s in json.loads(Path(args.manifest).read_text())]
    else:
        if not args.pcap:
            raise SystemExit("give a pcap file or --manifest")
        jobs = [(Path(p), args.label or Path(p).stem, args.lat, args.lon, None) for p in args.pcap]

    store = ProbeStore(args.db)
    for path, label, lat, lon, salt in jobs:
        session = store.start_session(label, lat, lon, f"pcap:{path.name}")
        recorder = Recorder(store, session, _anonymizer(args, salt), FixedLocation(lat, lon))
        print(f"{path.name}: {ingest_pcap(str(path), recorder)} probe requests -> session {session} ({label})")
    store.close()


def cmd_stats(args) -> None:
    from .stats import format_text, summarize
    from .store import ProbeStore
    s = summarize(ProbeStore(args.db).rows(), args.top)
    print(json.dumps(s, indent=2) if args.json else format_text(s))


def cmd_map(args) -> None:
    from .mapgen import build_map
    from .store import ProbeStore
    s = build_map(ProbeStore(args.db).rows(), args.out, args.title, args.redact_ssids, args.zoom)
    print(f"wrote {args.out}: {s['frames']} frames, {s['unique_macs']} MACs")


def cmd_export(args) -> None:
    from .store import ProbeStore
    print(f"wrote {ProbeStore(args.db).export_csv(args.csv)} rows to {args.csv}")


def cmd_synth(args) -> None:
    from .synth import generate
    print(f"wrote synthetic pcaps and {generate(args.out, args.seed)}")


def _privacy_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--store-raw-mac", action="store_true",
                   help="opt in: also store the real MAC (default: salted per-session token only)")
    p.add_argument("--salt-file", help="opt in: reuse a persistent salt so tokens link across sessions")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="eldrad", description="Passive 802.11 probe request logger")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("monitor", help="put a Linux interface into or out of monitor mode")
    p.add_argument("action", choices=["up", "down", "status"])
    p.add_argument("iface")
    p.add_argument("--dry-run", action="store_true", help="print the commands without running them")
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("capture", help="live passive capture on a monitor-mode interface (Linux, root)")
    p.add_argument("--iface", required=True)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--label", default="live")
    p.add_argument("--lat", type=float)
    p.add_argument("--lon", type=float)
    p.add_argument("--gpsd", action="store_true", help="tag frames with the gpsd fix (falls back to --lat/--lon)")
    p.add_argument("--channels", help="comma-separated channel list, default 2.4 GHz 1-11")
    p.add_argument("--dwell", type=float, default=0.5, help="seconds per channel")
    p.add_argument("--no-hop", action="store_true", help="stay on the current channel")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    _privacy_flags(p)
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("ingest", help="load probe requests from pcap files (e.g. WiFi Pineapple Pager)")
    p.add_argument("pcap", nargs="*")
    p.add_argument("--manifest", help="sessions.json listing pcap, label, lat, lon per session")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--label")
    p.add_argument("--lat", type=float)
    p.add_argument("--lon", type=float)
    _privacy_flags(p)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("stats", help="summary statistics")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("map", help="generate the Folium map")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--out", default="captures/map.html")
    p.add_argument("--title", default="eldrad-ulthran probe map")
    p.add_argument("--redact-ssids", action="store_true", help="replace SSIDs with short hashes")
    p.add_argument("--zoom", type=int, default=15)
    p.set_defaults(func=cmd_map)

    p = sub.add_parser("export", help="export the database to CSV")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--csv", required=True)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("synth", help="generate synthetic sample pcaps")
    p.add_argument("--out", default="samples")
    p.add_argument("--seed", type=int, default=40_000)
    p.set_defaults(func=cmd_synth)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
