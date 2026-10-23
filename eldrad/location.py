"""Where a frame was heard: a fixed per-session point, or a live fix from gpsd."""
from __future__ import annotations

import json
import socket
import threading
import time


class FixedLocation:
    def __init__(self, lat: float | None, lon: float | None):
        self.fix = (lat, lon)

    def current(self) -> tuple[float | None, float | None]:
        return self.fix

    def stop(self) -> None:
        pass


class GpsdLocation:
    """Follows gpsd's JSON stream (TCP 2947) and keeps the latest 2D/3D fix.

    Until the first fix arrives, or whenever gpsd drops out, the fallback point is used.
    """

    def __init__(self, fallback: FixedLocation, host: str = "127.0.0.1", port: int = 2947):
        self.fix = fallback.current()
        self.host, self.port = host, port
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def current(self) -> tuple[float | None, float | None]:
        return self.fix

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                with socket.create_connection((self.host, self.port), timeout=5) as sock:
                    sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
                    for line in sock.makefile("r"):
                        if self._stop.is_set():
                            return
                        msg = json.loads(line)
                        if msg.get("class") == "TPV" and msg.get("mode", 0) >= 2 and "lat" in msg:
                            self.fix = (msg["lat"], msg["lon"])
            except (OSError, ValueError):
                time.sleep(2)
