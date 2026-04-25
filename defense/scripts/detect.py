#!/usr/bin/env python3
"""
detect.py — Real-time DDoS Detection Daemon
Tails access.log every 5s, scores each IP with ML model,
writes flagged IPs to /tmp/sinkholes.txt for nginx geo map.
"""

import re, os, time, json, argparse, subprocess
from collections import defaultdict
from datetime import datetime
from math import log2
import numpy as np
import joblib

# ── Config ────────────────────────────────────────────────────────
LOG_FILE      = "/home/<YOUR_USER>/ddos-lab/server/logs/access.log"
MODEL_PATH    = "/home/<YOUR_USER>/ddos-lab/defense/models/best_model.pkl"
SCALER_PATH   = "/home/<YOUR_USER>/ddos-lab/defense/models/scaler.pkl"
SINKHOLE_FILE = "/tmp/sinkholes.txt"          # nginx geo map reads this
DETECT_LOG    = "/home/<YOUR_USER>/ddos-lab/defense/detections.log"
NGINX_CONF    = "/home/<YOUR_USER>/ddos-lab/server/nginx/sinkholes.conf"

SCAN_INTERVAL = 5        # seconds between scans
THRESHOLD     = 0.60     # probability to flag as attack
WINDOW_SEC    = 10       # feature extraction window
MIN_REQS      = 5        # ignore IPs with fewer requests in window

FEATURE_COLS = [
    'req_rate', 'inter_mean', 'inter_std', 'unique_urls',
    'url_entropy', 'pct_heavy', 'pct_5xx', 'pct_200',
    'ua_entropy', 'pct_ab', 'pct_ddosbot', 'dur_mean',
    'dur_std', 'bytes_mean',
]

# IPs that should never be blocked (legit traffic VM, monitoring)
WHITELIST = {'<LEGIT_TRAFFIC_EXTERNAL_IP>', '127.0.0.1', '172.20.0.1'}  # ← Add your legit traffic VM's external IP

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<ua>[^"]*)" (?P<dur>\S+)$'
)

# ── Helpers ───────────────────────────────────────────────────────
def entropy(values):
    if not values: return 0.0
    from collections import Counter
    c = Counter(values)
    t = len(values)
    return -sum((n/t) * log2(n/t) for n in c.values())

def ts_parse(ts_str):
    try:
        s = ts_str.replace('+00:00','').replace('T',' ')
        return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
    except:
        return None

def log_event(msg):
    ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    line = f"[{ts}] {msg}"
    print(line)
    with open(DETECT_LOG, 'a') as f:
        f.write(line + '\n')

# ── Feature extraction for a single IP's request window ──────────
def extract_features(reqs):
    n       = len(reqs)
    rr      = n / WINDOW_SEC
    ts_secs = sorted([(r['ts'] - reqs[0]['ts']).total_seconds() for r in reqs])
    diffs   = [ts_secs[i+1] - ts_secs[i] for i in range(len(ts_secs)-1)]
    paths   = [r['path']   for r in reqs]
    statuses= [r['status'] for r in reqs]
    uas     = [r['ua']     for r in reqs]
    durs    = [r['dur']    for r in reqs]
    bytes_  = [r['bytes']  for r in reqs]

    return [
        round(rr, 4),
        round(np.mean(diffs) if diffs else 0, 4),
        round(np.std(diffs)  if diffs else 0, 4),
        len(set(paths)),
        round(entropy(paths), 4),
        round(sum(1 for p in paths   if '/heavy' in p) / n, 4),
        round(sum(1 for s in statuses if s >= 500)      / n, 4),
        round(sum(1 for s in statuses if s == 200)      / n, 4),
        round(entropy(uas), 4),
        round(sum(1 for u in uas if 'ApacheBench' in u) / n, 4),
        round(sum(1 for u in uas if 'DDoS-Bot'    in u) / n, 4),
        round(np.mean(durs), 4),
        round(np.std(durs),  4),
        round(np.mean(bytes_), 4),
    ]

# ── Sinkhole management ───────────────────────────────────────────
def add_to_sinkhole(ip):
    """Write IP to sinkholes.txt and sinkholes.conf, reload nginx."""
    # sinkholes.txt — simple list for tracking
    with open(SINKHOLE_FILE, 'a') as f:
        f.write(ip + '\n')

    # sinkholes.conf — nginx geo map format
    os.makedirs(os.path.dirname(NGINX_CONF), exist_ok=True)
    existing = set()
    if os.path.exists(NGINX_CONF):
        with open(NGINX_CONF) as f:
            existing = set(f.read().splitlines())

    entry = f"{ip} 1;"
    if entry not in existing:
        with open(NGINX_CONF, 'a') as f:
            f.write(entry + '\n')
        # Reload nginx to pick up new sinkhole entry
        subprocess.run(
            ['docker', 'exec', 'ddos-nginx', 'nginx', '-s', 'reload'],
            capture_output=True
        )

# ── Main detection loop ───────────────────────────────────────────
def run(threshold, whitelist_extra):
    whitelist = WHITELIST | set(whitelist_extra)

    print("=" * 60)
    print("  DDoS ML Detection Daemon")
    print("=" * 60)
    print(f"  Log file   : {LOG_FILE}")
    print(f"  Model      : {MODEL_PATH}")
    print(f"  Threshold  : prob >= {threshold}")
    print(f"  Scan every : {SCAN_INTERVAL}s")
    print(f"  Whitelist  : {whitelist}")
    print("=" * 60)

    # Load model
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("  ✅ Model loaded\n")

    # Track state
    sinkholes    = set()   # IPs already sinkholes
    file_offset  = 0       # where we left off in log file

    # Seek to end of log on startup (only watch new lines)
    if os.path.exists(LOG_FILE):
        file_offset = os.path.getsize(LOG_FILE)

    print(f"  {'Time':<10} {'Status':<12} {'IP':<20} {'Prob':>6}  {'Reqs':>5}  Reason")
    print(f"  {'-'*70}")

    while True:
        time.sleep(SCAN_INTERVAL)

        # Read new lines since last scan
        new_records = []
        try:
            with open(LOG_FILE, 'r', errors='ignore') as f:
                f.seek(file_offset)
                new_lines = f.readlines()
                file_offset = f.tell()
        except FileNotFoundError:
            continue

        if not new_lines:
            continue

        # Parse new lines
        for line in new_lines:
            m = LOG_RE.match(line.strip())
            if not m: continue
            ts = ts_parse(m.group('ts'))
            if not ts: continue
            try:
                new_records.append({
                    'ip':     m.group('ip'),
                    'ts':     ts,
                    'path':   m.group('path'),
                    'status': int(m.group('status')),
                    'bytes':  int(m.group('bytes')),
                    'ua':     m.group('ua'),
                    'dur':    float(m.group('dur')),
                })
            except:
                continue

        if not new_records:
            continue

        ts_now = datetime.utcnow().strftime('%H:%M:%S')
        print(f"\n  ── {ts_now}  {len(new_lines):,} new lines ──────────────────")

        # Group by IP
        by_ip = defaultdict(list)
        for r in new_records:
            if r['ip'].startswith('172.20'):
                continue  # skip Docker internal
            by_ip[r['ip']].append(r)

        # Score each IP
        for ip, reqs in by_ip.items():
            if ip in whitelist:
                continue
            if len(reqs) < MIN_REQS:
                continue

            features = extract_features(sorted(reqs, key=lambda r: r['ts']))
            X = scaler.transform([features])
            prob = model.predict_proba(X)[0][1]

            # Build reason string
            f = dict(zip(FEATURE_COLS, features))
            reasons = []
            if f['req_rate']  > 10:  reasons.append(f"req_rate={f['req_rate']:.0f}/s")
            if f['pct_ab']    > 0.5: reasons.append(f"ApacheBench={f['pct_ab']*100:.0f}%")
            if f['pct_heavy'] > 0.5: reasons.append(f"heavy={f['pct_heavy']*100:.0f}%")
            if f['pct_5xx']   > 0.3: reasons.append(f"5xx={f['pct_5xx']*100:.0f}%")
            reason_str = ', '.join(reasons) if reasons else 'anomaly'

            if prob >= threshold:
                if ip not in sinkholes:
                    sinkholes.add(ip)
                    add_to_sinkhole(ip)
                    status = '[SINKHOLED]'
                    log_event(f"[SINKHOLED] {ip}  prob={prob:.3f}  reqs={len(reqs)}  {reason_str}")
                else:
                    status = '[REPEAT]   '

                print(f"  {ts_now:<10} {status:<12} {ip:<20} {prob:>6.3f}  {len(reqs):>5}  {reason_str}")
            else:
                if len(reqs) > MIN_REQS:
                    print(f"  {ts_now:<10} {'[CLEAN]':<12} {ip:<20} {prob:>6.3f}  {len(reqs):>5}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--threshold', type=float, default=THRESHOLD)
    parser.add_argument('--whitelist', nargs='*', default=[])
    args = parser.parse_args()

    os.makedirs(os.path.dirname(DETECT_LOG), exist_ok=True)
    run(args.threshold, args.whitelist)
