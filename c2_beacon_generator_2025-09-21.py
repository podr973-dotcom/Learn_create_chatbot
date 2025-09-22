"""
c2_beacon_generator_2025-09-21.py

Generates a synthetic CSV of C2 beaconing traffic for a single infected host
running Cobalt Strike over the 24-hour period of 2025-09-21 (Asia/Singapore tz).

- Base sleep: 30 seconds
- Jitter: uniform +/-20 seconds (clipped to >= 1s)
- Deterministic RNG (seed) for reproducibility
- Output CSV: c2_beacons_2025-09-21.csv

Dependencies: pytz (install: pip install pytz)
Run: python c2_beacon_generator_2025-09-21.py
"""

import csv
import uuid
import random
from datetime import datetime, timedelta

import pytz

# --------------------- Parameters (edit if desired) ---------------------
BASE_SLEEP = 30.0          # seconds
JITTER_SECS = 20.0         # +/- seconds
SRC_IP = "10.0.0.5"
SRC_PORT = 49212
DST_IP = "198.51.100.23"
DST_PORT = 443
PROTO = "TCP"
TOOL = "Cobalt Strike"
BEACON_ID = str(uuid.uuid4())
SEED = 42
OUTFILE = "c2_beacons_2025-09-21.csv"

# Explicit date window: yesterday relative to 2025-09-22 -> 2025-09-21 00:00:00+08:00 -> 23:59:59+08:00
tz = pytz.timezone("Asia/Singapore")
start = tz.localize(datetime(2025, 9, 21, 0, 0, 0))
end = tz.localize(datetime(2025, 9, 21, 23, 59, 59))

random.seed(SEED)

# --------------------- Small helper generators ---------------------

def make_ja3():
    """Return a synthetic JA3-like string for the tls_ja3 field."""

    parts = [str(random.randint(0, 65535)) for _ in range(5)]
    return "-".join(parts)


def make_uri():
    """Pick a plausible URI path for a beacon request."""

    choices = [
        "/updates/check",
        "/images/logo.png",
        "/api/v1/poll",
        "/status",
        "/client/report",
        "/assets/config",
    ]
    return random.choice(choices)


def make_user_agent():
    """Return a browser-like user agent string."""

    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    ]
    return random.choice(uas) + " (KHTML, like Gecko)"


# CSV fields
fields = [
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "beacon_id",
    "seq",
    "http_method",
    "uri_path",
    "user_agent",
    "bytes_sent",
    "bytes_received",
    "duration_ms",
    "tls_ja3",
    "tool",
]

rows = []
current = start
seq = 0

while current <= end:
    seq += 1
    jitter = random.uniform(-JITTER_SECS, JITTER_SECS)
    interval = max(1.0, BASE_SLEEP + jitter)

    bytes_sent = random.randint(80, 400)
    bytes_received = random.randint(0, 2500)
    duration_ms = random.randint(20, 800)
    ja3 = make_ja3()
    uri = make_uri()
    ua = make_user_agent()

    rows.append(
        {
            "timestamp": current.isoformat(),
            "src_ip": SRC_IP,
            "src_port": SRC_PORT,
            "dst_ip": DST_IP,
            "dst_port": DST_PORT,
            "protocol": PROTO,
            "beacon_id": BEACON_ID,
            "seq": seq,
            "http_method": "POST" if random.random() < 0.7 else "GET",
            "uri_path": uri,
            "user_agent": ua,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_ms": duration_ms,
            "tls_ja3": ja3,
            "tool": TOOL,
        }
    )

    current = current + timedelta(seconds=interval)

# Write CSV
with open(OUTFILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

print(f"Wrote {len(rows)} rows to {OUTFILE}")
