#!/usr/bin/env python3
"""
Legitimate Traffic Generator
Westbrook University — simulated European student visitors
VM: e2-micro, europe-north1
"""

import requests
import random
import time
import threading
import sys
from datetime import datetime

TARGET = "http://<SERVER_EXTERNAL_IP>"  # ← Change to your server's static external IP

USER_AGENTS = [
    # Desktop browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; Samsung Galaxy S21) AppleWebKit/537.36 Mobile Safari/537.36",
]

# Realistic browsing journeys a prospective student would take
JOURNEYS = [
    # Prospective student checking programs
    ["/", "/pages/programs.html", "/pages/admissions.html"],
    # Researcher browsing
    ["/", "/pages/research.html", "/pages/about.html"],
    # Quick visitor
    ["/index.html", "/pages/about.html"],
    # Mobile user checking admissions
    ["/", "/pages/admissions.html"],
    # Full browse
    ["/", "/pages/programs.html", "/pages/about.html", "/pages/research.html", "/pages/admissions.html"],
    # API check (simulates JS on the page loading data)
    ["/", "/api/data", "/pages/programs.html"],
    # Direct page visit from search
    ["/pages/admissions.html", "/", "/pages/programs.html"],
    # Short visit
    ["/index.html"],
]

REFERRERS = [
    "https://www.google.com/search?q=westbrook+university+programs",
    "https://www.google.co.uk/search?q=westbrook+university+admissions",
    "https://www.bing.com/search?q=westbrook+university",
    "https://uk.linkedin.com/school/westbrook-university",
    "https://twitter.com/westbrook_uni",
    "",  # direct
    "",  # direct
    "",  # direct
]

ACCEPT_LANGUAGES = [
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9",
    "fi-FI,fi;q=0.9,en;q=0.8",
    "sv-SE,sv;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.7",
    "no-NO,no;q=0.9,en;q=0.8",
]

# ── stats shared across threads ───────────────────────────────────
stats = {"total": 0, "ok": 0, "failed": 0, "lock": threading.Lock()}


class Student:
    def __init__(self, uid):
        self.uid        = uid
        self.ua         = random.choice(USER_AGENTS)
        self.lang       = random.choice(ACCEPT_LANGUAGES)
        self.referer    = random.choice(REFERRERS)
        self.session    = requests.Session()
        self.hops       = 0

    def visit(self, path):
        headers = {
            "User-Agent":      self.ua,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": self.lang,
            "Accept-Encoding": "gzip, deflate",
            "Referer":         self.referer if self.hops > 0 else "",
            "Connection":      "keep-alive",
            "DNT":             "1",
        }
        try:
            r = self.session.get(
                f"{TARGET}{path}",
                headers=headers,
                timeout=30
            )
            self.hops   += 1
            self.referer = f"{TARGET}{path}"
            return r.status_code
        except requests.exceptions.Timeout:
            return 408
        except Exception:
            return 0


def run_student(uid):
    s       = Student(uid)
    journey = random.choice(JOURNEYS)
    ts      = datetime.now().strftime("%H:%M:%S")

    for path in journey:
        status = s.visit(path)
        icon   = "✅" if status == 200 else ("⚠️ " if status == 408 else "❌")

        with stats["lock"]:
            stats["total"] += 1
            if status == 200:
                stats["ok"] += 1
            elif status != 0:
                stats["failed"] += 1

        print(f"  [{ts}] {icon} Student-{uid:03d}  {path:<38}  HTTP {status}")

        # Realistic reading time between page clicks
        if path != journey[-1]:
            time.sleep(random.uniform(2.0, 6.0))


def banner():
    print("")
    print("╔══════════════════════════════════════════════════════╗")
    print("║     WESTBROOK UNIVERSITY — TRAFFIC SIMULATOR        ║")
    print("║     Source: europe-north1 (Finland)                 ║")
    print(f"║     Target: {TARGET:<40}║")
    print("╚══════════════════════════════════════════════════════╝")
    print("")


def run(num_students=3, wave_interval=6):
    banner()
    print(f"  Students per wave : {num_students}")
    print(f"  Wave interval     : {wave_interval}s")
    print(f"  Press Ctrl+C to stop")
    print("")

    wave = 0
    try:
        while True:
            wave += 1
            print(f"─── Wave {wave} ({'normal' if stats['failed'] == 0 else '⚠️  some failures — server may be under attack'}) ───")

            threads = []
            base_uid = wave * num_students

            for i in range(num_students):
                t = threading.Thread(
                    target=run_student,
                    args=(base_uid + i,),
                    daemon=True
                )
                threads.append(t)
                t.start()
                # Stagger starts slightly — more realistic
                time.sleep(random.uniform(0.3, 1.2))

            for t in threads:
                t.join()

            # Summary line
            with stats["lock"]:
                total  = stats["total"]
                ok     = stats["ok"]
                failed = stats["failed"]

            pct = round(ok / total * 100) if total > 0 else 0
            print(f"\n  Wave {wave} done — running total: {ok}/{total} successful ({pct}%)")
            if failed > 0:
                print(f"  ⚠️  {failed} failed requests — server likely under attack right now!")
            print("")

            time.sleep(wave_interval)

    except KeyboardInterrupt:
        with stats["lock"]:
            total  = stats["total"]
            ok     = stats["ok"]
            failed = stats["failed"]
        print(f"\n  Stopped after {wave} waves")
        print(f"  Total: {total}  ✅ {ok}  ❌ {failed}")
        print("")


if __name__ == "__main__":
    students = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    run(students, interval)
