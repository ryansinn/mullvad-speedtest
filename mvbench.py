#!/usr/bin/env python3
"""mvbench - survey Mullvad exit relays and keep the history.

A run switches the live tunnel, so expect brief drops (lockdown mode blocks
traffic during switches rather than leaking it). When it finishes, the previous
relay constraint is restored.

  ./mvbench.py plan                 # relays the next run would test, no switching
  ./mvbench.py run                  # best-rated relays first, retest way-off results at the end
  ./mvbench.py watch                # live progress in this terminal until it finishes
  ./mvbench.py report               # per-relay stats in the recent window
  ./mvbench.py patterns             # all history, by country, city, and relay
  ./mvbench.py recommend            # best surveyed relays against the benchmark
  ./mvbench.py apply                # load the best relays into Mullvad and select that list
  ./mvbench.py connect              # pin to the single best surveyed relay
  ./mvbench.py restore              # put the pre-run relay constraint back
  ./mvbench.py block add|rm|ls PAT  # glob blocklist, e.g. us-mia-* or us-lax-wg-403
"""
import argparse
import fnmatch
import json
import os
import random
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.toml"
BLOCKLIST_PATH = HERE / "blocklist.txt"
DB_PATH = HERE / "mvbench.db"
LOCK_PATH = HERE / "mvbench.lock"
RESTORE_PATH = HERE / "mvbench.restore"

DEFAULTS = {
    "country": "",
    "countries": ["us", "ca", "mx"],
    "benchmark_countries": ["se"],
    "benchmark_per_run": 4,
    "cities": [],
    "ownership": "any",
    "providers": [],
    "relays_per_run": 26,
    "settle_seconds": 2.0,
    "connect_timeout": 25.0,
    "download_urls": [
        "https://speed.cloudflare.com/__down?bytes=60000000",
        "https://ash-speed.hetzner.com/100MB.bin",
    ],
    "download_max_time": 10,
    "ping_target": "1.1.1.1",
    "ping_count": 10,
    "window_days": 14,
    "min_samples": 2,
    "custom_list": "mvbench-best",
    "top_n": 5,
    "max_ping_ms": 0,
    "service_checks": [],
    "seconds_per_relay": 20,
    "outlier_mad": 2.5,          # spread multiplier for "way off" versus this run
    "speed_outlier_score": 1.0, # speed must clear this many limits
    "ping_outlier_score": 1.5,  # ping must clear more, because distance is real
    "retest_limit": 8,           # flagged relays retested once at the end
    "agree_ratio": 0.25,         # two tests agree when speed and ping are within this
}

COUNTRY_NAMES = {
    "us": "US", "ca": "Canada", "mx": "Mexico", "se": "Sweden",
}

LINE_RE = re.compile(
    r"^\t\t(?P<host>[a-z]{2}-[a-z]{3}-wg-[0-9a-z]+) \((?P<ipv4>[0-9.]+)[^)]*\) - hosted by (?P<provider>.+?) \((?P<own>Mullvad-owned|rented)\)"
)
CITY_RE = re.compile(r"^\t(?P<name>.+?) \((?P<code>[a-z]{3})\) @")
COUNTRY_RE = re.compile(r"^(?P<name>\S.*?) \((?P<code>[a-z]{2})\)$")

ALT_ON = "\033[?1049h\033[?25l\033[?7l"
ALT_OFF = "\033[?7h\033[?25h\033[?1049l"


# ---------- config / blocklist ----------

def load_config():
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            cfg.update(tomllib.load(f))
    return cfg


def survey_countries(cfg):
    raw = [c.lower() for c in (cfg.get("countries") or []) if c]
    if not raw and cfg.get("country"):
        raw = [cfg["country"].lower()]
    if not raw:
        raw = ["us", "ca", "mx"]
    bench = set(benchmark_countries(cfg))
    return [c for c in raw if c not in bench]


def benchmark_countries(cfg):
    return [c.lower() for c in (cfg.get("benchmark_countries") or []) if c]


def scope_title(survey, bench):
    if set(survey) == {"us", "ca", "mx"} and bench == ["se"]:
        return "North America vs Sweden"
    left = ", ".join(COUNTRY_NAMES.get(c, c) for c in survey) or "survey"
    right = ", ".join(COUNTRY_NAMES.get(c, c) for c in bench)
    return f"{left} vs {right}" if right else left


def load_blocklist():
    if not BLOCKLIST_PATH.exists():
        return []
    pats = []
    for line in BLOCKLIST_PATH.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            pats.append(line)
    return pats


def is_blocked(host, pats):
    return any(fnmatch.fnmatch(host, p) for p in pats)


# ---------- mullvad CLI ----------

def mv(*args, check=True):
    r = subprocess.run(["mullvad", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"mullvad {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def list_relays():
    relays, country, city = [], None, None
    for line in mv("relay", "list").splitlines():
        if m := COUNTRY_RE.match(line):
            country = m["code"]
        elif m := CITY_RE.match(line):
            city = (m["code"], m["name"])
        elif m := LINE_RE.match(line):
            relays.append({
                "host": m["host"], "ipv4": m["ipv4"], "country": country,
                "city": city[0], "city_name": city[1],
                "provider": m["provider"], "owned": m["own"] == "Mullvad-owned",
            })
    return relays


def keep_relay(r, countries, cfg, pats, cities_matter):
    if r["country"] not in countries:
        return False
    if cities_matter and cfg["cities"] and r["city"] not in cfg["cities"]:
        return False
    if cfg["ownership"] == "owned" and not r["owned"]:
        return False
    if cfg["ownership"] == "rented" and r["owned"]:
        return False
    if cfg["providers"] and r["provider"] not in cfg["providers"]:
        return False
    if is_blocked(r["host"], pats):
        return False
    return True


def pools(cfg, relays=None):
    relays = list_relays() if relays is None else relays
    pats = load_blocklist()
    survey = [r for r in relays if keep_relay(r, survey_countries(cfg), cfg, pats, True)]
    bench = [r for r in relays if keep_relay(r, benchmark_countries(cfg), cfg, pats, False)]
    return survey, bench


def status():
    return json.loads(mv("status", "-j"))


def current_hostname():
    try:
        s = status()
    except (RuntimeError, json.JSONDecodeError):
        return None
    if s.get("state") != "connected":
        return None
    return s.get("details", {}).get("location", {}).get("hostname")


def current_location_args():
    """Parse `mullvad relay get` so the run can restore the previous constraint."""
    out = mv("relay", "get")
    m = re.search(r"Location:\s+(.+)", out)
    if not m:
        return None
    loc = m.group(1).strip()
    if loc in mv("custom-list", "list").splitlines():
        return ["custom-list", loc]
    if hosts := re.findall(r"[a-z]{2}-[a-z]{3}-wg-[0-9a-z]+", loc):
        return ["location", hosts[0]]
    if loc == "any":
        return ["location", "any"]
    if m := re.fullmatch(r"city ([a-z]{3}), ([a-z]{2})", loc):
        return ["location", m.group(2), m.group(1)]
    if m := re.fullmatch(r"country ([a-z]{2})", loc):
        return ["location", m.group(1)]
    return None


def connect_to(host, timeout):
    t0 = time.monotonic()
    mv("relay", "set", "location", host)
    mv("connect", check=False)
    while time.monotonic() - t0 < timeout:
        try:
            s = status()
        except (RuntimeError, json.JSONDecodeError):
            s = {}
        if s.get("state") == "connected" and s.get("details", {}).get("location", {}).get("hostname") == host:
            return time.monotonic() - t0
        time.sleep(0.5)
    return None


def apply_restore(args):
    if not args:
        return False
    mv("relay", "set", *args, check=False)
    mv("connect", check=False)
    if RESTORE_PATH.exists():
        RESTORE_PATH.unlink()
    return True


# ---------- measurements ----------

def measure_ping(target, count):
    r = subprocess.run(
        ["ping", "-n", "-q", "-c", str(count), "-i", "0.2", "-W", "2", target],
        capture_output=True, text=True)
    loss = re.search(r"([\d.]+)% packet loss", r.stdout)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", r.stdout)
    return (
        float(rtt.group(2)) if rtt else None,
        float(rtt.group(4)) if rtt else None,
        float(loss.group(1)) if loss else 100.0,
    )


def measure_download(urls, max_time):
    last_err = "no urls"
    for url in urls:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--connect-timeout", "5", "--max-time", str(max_time),
             "-w", "%{http_code} %{speed_download} %{size_download} %{time_starttransfer}", url],
            capture_output=True, text=True)
        parts = r.stdout.split()
        if len(parts) == 4 and parts[0] == "200":
            bytes_per_s, size = float(parts[1]), int(float(parts[2]))
            if size > 0:
                return bytes_per_s * 8 / 1e6, float(parts[3]), None
        last_err = f"{url.split('/')[2]}: http={parts[0] if parts else '?'} curl_exit={r.returncode}"
    return 0.0, None, last_err


def run_service_checks(checks):
    failed = []
    for c in checks:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-L", "--max-time", "10", "-w", "%{http_code}", c["url"]],
            capture_output=True, text=True)
        expect = int(c.get("expect_status", 200))
        if r.stdout.strip() != str(expect):
            failed.append(f"{c.get('name', c['url'])}={r.stdout.strip() or 'ERR'}")
    return failed


# ---------- storage ----------

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    con.execute("""CREATE TABLE IF NOT EXISTS tests (
        id INTEGER PRIMARY KEY, ts TEXT NOT NULL, host TEXT NOT NULL, city TEXT, provider TEXT,
        owned INTEGER, connect_s REAL, ping_ms REAL, jitter_ms REAL, loss_pct REAL,
        mbps REAL, ttfb_s REAL, error TEXT, service_fail TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS tests_host_ts ON tests(host, ts)")
    have = {row[1] for row in con.execute("PRAGMA table_info(tests)")}
    for name, decl in (("run_id", "TEXT"), ("country", "TEXT"), ("benchmark", "INTEGER"),
                        ("city_name", "TEXT"), ("flag", "TEXT")):
        if name not in have:
            con.execute(f"ALTER TABLE tests ADD COLUMN {name} {decl}")
    con.execute("UPDATE tests SET country = substr(host, 1, 2) WHERE country IS NULL AND host IS NOT NULL")
    con.execute("""CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        started TEXT NOT NULL,
        finished TEXT,
        status TEXT NOT NULL,
        planned INTEGER,
        tested INTEGER DEFAULT 0,
        current_host TEXT,
        phase TEXT,
        scope TEXT,
        title TEXT,
        restore TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS tests_run ON tests(run_id)")
    con.commit()
    return con


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(ts):
    return datetime.fromisoformat(ts)


def seen_counts():
    con = db()
    try:
        return {row["host"]: (row["c"], row["last"]) for row in con.execute(
            "SELECT host, COUNT(*) c, MAX(ts) last FROM tests GROUP BY host")}
    finally:
        con.close()


def fetch_run(run_id=None):
    con = db()
    try:
        if run_id:
            run = con.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        else:
            run = con.execute("SELECT * FROM runs ORDER BY started DESC LIMIT 1").fetchone()
        if run is None:
            return None, []
        run = dict(run)
        rows = [dict(r) for r in con.execute("SELECT * FROM tests WHERE run_id = ? ORDER BY id", (run["id"],))]
        return run, rows
    finally:
        con.close()


# ---------- selection ----------

def pick_spread(relays, n, seen):
    """One relay per city first, countries interleaved, least-tested relay in each city.

    A second relay from a city is only taken after every city has been visited.
    """
    if n <= 0 or not relays:
        return []
    by = {}
    for r in relays:
        by.setdefault(r["country"], {}).setdefault(r["city"], []).append(dict(r))
    per_country = {}
    for country, cities in by.items():
        units = []
        for rels in cities.values():
            random.shuffle(rels)
            rels.sort(key=lambda r: seen.get(r["host"], (0, "")))
            units.append(rels)
        random.shuffle(units)
        units.sort(key=lambda rels: seen.get(rels[0]["host"], (0, "")))
        per_country[country] = units
    order = [c for c in ("us", "ca", "mx") if c in per_country]
    order += sorted(c for c in per_country if c not in order)
    sequence, stalled, i = [], 0, 0
    while stalled < len(order):
        units = per_country[order[i % len(order)]]
        i += 1
        if not units:
            stalled += 1
            continue
        stalled = 0
        sequence.append(units.pop(0))
    picked = []
    while len(picked) < n and any(rels for rels in sequence):
        for rels in sequence:
            if len(picked) >= n:
                break
            if rels:
                picked.append(rels.pop(0))
    return picked


def pick_benchmark(relays, n, seen, current_host):
    picked = pick_spread(relays, n, seen)
    cur = next((r for r in relays if r["host"] == current_host), None)
    if cur is None:
        return picked
    picked = [r for r in picked if r["host"] != cur["host"]]
    return [cur, *picked][:n]


def history_stats(rows=None):
    """Per-relay averages from successful tests. Failures are left out of the averages."""
    if rows is None:
        rows = load_history()
    by = {}
    for row in rows:
        row = dict(row)
        if row.get("error") or not row.get("mbps"):
            continue
        by.setdefault(row["host"], []).append(row)
    stats = {}
    for host, tests in by.items():
        speeds = [t["mbps"] for t in tests]
        pings = [t["ping_ms"] for t in tests if t["ping_ms"] is not None]
        stats[host] = {
            "n": len(speeds),
            "avg_mbps": statistics.fmean(speeds),
            "med_mbps": statistics.median(speeds),
            "avg_ping": statistics.fmean(pings) if pings else None,
            "med_ping": statistics.median(pings) if pings else None,
        }
    return stats


def confirmed_poor(st, overall_med):
    """Two or more samples, and the relay's own median is well below the pack."""
    if not st or st["n"] < 2 or not overall_med:
        return False
    return st["med_mbps"] < overall_med * 0.6


def pick_city_relay(rels, stats, overall_med, seen):
    """Best-rated relay in the city, unless that relay has already proved slow."""
    usable = [r for r in rels if not confirmed_poor(stats.get(r["host"]), overall_med)]
    if not usable:
        usable = list(rels)
    rated = [r for r in usable if r["host"] in stats]
    if rated:
        rated.sort(key=lambda r: (-stats[r["host"]]["med_mbps"], stats[r["host"]]["med_ping"] or 1e9))
        return rated[0]
    random.shuffle(usable)
    usable.sort(key=lambda r: seen.get(r["host"], (0, "")))
    return usable[0]


def order_best_first(picked, stats):
    rated = [r for r in picked if r["host"] in stats]
    fresh = [r for r in picked if r["host"] not in stats]
    rated.sort(key=lambda r: (-stats[r["host"]]["med_mbps"], stats[r["host"]]["med_ping"] or 1e9))
    by_country = {}
    for r in fresh:
        by_country.setdefault(r["country"], []).append(r)
    order = [c for c in ("us", "ca", "mx") if c in by_country]
    order += sorted(c for c in by_country if c not in order)
    interleaved, stalled, i = [], 0, 0
    while order and stalled < len(order):
        bucket = by_country[order[i % len(order)]]
        i += 1
        if not bucket:
            stalled += 1
            continue
        stalled = 0
        interleaved.append(bucket.pop(0))
    return rated + interleaved


def choose_benchmark(relays, n, seen, stats, current):
    """Best-rated benchmark relays, current exit first, then a relay from any city still missing."""
    if n <= 0 or not relays:
        return []
    by_city = {}
    for r in relays:
        by_city.setdefault(r["city"], []).append(r)
    ranked = order_best_first(relays, stats)
    med = median_or_none([stats[r["host"]]["med_mbps"] for r in relays if r["host"] in stats])
    picked, seen_hosts = [], set()

    def add(relay):
        if relay and relay["host"] not in seen_hosts and len(picked) < n:
            picked.append(relay)
            seen_hosts.add(relay["host"])

    if current:
        add(next((r for r in relays if r["host"] == current), None))
    for r in ranked:
        if r["host"] in stats:
            add(r)
    covered = {r["city"] for r in picked}
    for city, rels in by_city.items():
        if city not in covered:
            add(pick_city_relay(rels, stats, med, seen))
    for r in ranked:
        add(r)
    return picked


def choose_targets(cfg, relays, na_n, bench_n):
    survey, bench = pools(cfg, relays)
    seen = seen_counts()
    stats = history_stats()
    current = current_hostname()
    survey_hosts = {r["host"] for r in survey}
    survey_med = median_or_none([st["med_mbps"] for h, st in stats.items() if h in survey_hosts])
    bench_pick = choose_benchmark(bench, bench_n, seen, stats, current)
    by_city = {}
    for r in survey:
        by_city.setdefault((r["country"], r["city"]), []).append(r)
    one_each = [pick_city_relay(rels, stats, survey_med, seen) for rels in by_city.values()]
    survey_pick = order_best_first(one_each, stats)[:na_n]
    return [(r, True) for r in bench_pick] + [(r, False) for r in survey_pick]


# ---------- scoring ----------

def percentile(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def median_or_none(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None


def mean_or_none(vals):
    vals = [v for v in vals if v is not None]
    return statistics.fmean(vals) if vals else None


def mad(vals):
    if not vals:
        return 0.0
    med = statistics.median(vals)
    return statistics.median([abs(v - med) for v in vals]) or 0.0


def deviation_score(value, vals, mad_mult):
    """How many 'way off' limits this value exceeds. 0 means it sits with the pack."""
    if value is None or len(vals) < 4:
        return 0.0
    med = statistics.median(vals)
    if med == 0:
        return 0.0
    dev = abs(value - med)
    if len(vals) < 6:
        limit = abs(med) * 0.45
    else:
        limit = mad_mult * max(mad(vals), abs(med) * 0.10)
    if limit <= 0 or dev <= limit:
        return 0.0
    return dev / limit


def outlier_reason(row, peers, own, cfg):
    """Flag a result that is far from this run's pack, or far from the relay's own history.

    Peer speed and ping are judged separately for benchmark relays and survey relays,
    so a far country is not flagged just for being that country. Ping still varies
    inside a country; the retest is what decides whether a tail was a fluke.
    """
    if row.get("error"):
        return "failed", 10.0
    speeds = [p["mbps"] for p in peers if p.get("mbps") and not p.get("error")]
    pings = [p["ping_ms"] for p in peers if p.get("ping_ms") is not None and not p.get("error")]
    mult = cfg.get("outlier_mad", 2.5)
    reasons = []
    score = 0.0
    speed_z = deviation_score(row.get("mbps"), speeds, mult)
    ping_z = deviation_score(row.get("ping_ms"), pings, mult)
    # A relay that already measures like this is not a fluke. Retest it once, then stop.
    if own and own["n"] >= 2 and own["med_mbps"] and row.get("mbps"):
        if abs(row["mbps"] - own["med_mbps"]) <= 0.25 * own["med_mbps"]:
            speed_z = 0.0
    if own and own["n"] >= 2 and own["med_ping"] and row.get("ping_ms"):
        if abs(row["ping_ms"] - own["med_ping"]) <= max(20, 0.25 * own["med_ping"]):
            ping_z = 0.0
    if speed_z >= cfg.get("speed_outlier_score", 1.0):
        reasons.append("speed")
        score = max(score, speed_z)
    if ping_z >= cfg.get("ping_outlier_score", 1.5):
        reasons.append("ping")
        score = max(score, ping_z)
    if own and own["n"] >= 2:
        if own["med_mbps"] and row.get("mbps") and abs(row["mbps"] - own["med_mbps"]) > 0.4 * own["med_mbps"]:
            reasons.append("speed vs itself")
            score = max(score, 1.2)
        if own["med_ping"] and row.get("ping_ms") and abs(row["ping_ms"] - own["med_ping"]) > 0.4 * own["med_ping"]:
            reasons.append("ping vs itself")
            score = max(score, 1.2)
    if not reasons:
        return "", 0.0
    return "+".join(reasons), score


def select_retests(rows, prior, cfg):
    groups = {True: [], False: []}
    for row in rows:
        if not row.get("error"):
            groups[bool(row.get("benchmark"))].append(row)
    ranked = []
    for row in rows:
        reason, score = outlier_reason(row, groups[bool(row.get("benchmark"))], prior.get(row["host"]), cfg)
        if reason:
            ranked.append((score, row, reason))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[: cfg.get("retest_limit", 8)]


def results_agree(a, b, ratio):
    if bool(a.get("error")) != bool(b.get("error")):
        return False
    if a.get("error") and b.get("error"):
        return True
    hi = max(a.get("mbps") or 0, b.get("mbps") or 0, 1)
    if abs((a.get("mbps") or 0) - (b.get("mbps") or 0)) / hi > ratio:
        return False
    if a.get("ping_ms") is not None and b.get("ping_ms") is not None:
        hp = max(a["ping_ms"], b["ping_ms"], 1)
        if abs(a["ping_ms"] - b["ping_ms"]) / hp > ratio and abs(a["ping_ms"] - b["ping_ms"]) > 20:
            return False
    return True


def collapse_rows(rows, ratio):
    """One row per relay. Agreeing retests are averaged. Disagreeing ones are set aside."""
    order, by = [], {}
    for row in rows:
        if row["host"] not in by:
            order.append(row["host"])
            by[row["host"]] = []
        by[row["host"]].append(row)
    reps, checks = [], []
    for host in order:
        tests = by[host]
        if len(tests) == 1:
            reps.append(tests[0])
            continue
        first, last = tests[0], tests[-1]
        agree = results_agree(first, last, ratio)
        checks.append({"first": first, "second": last, "agree": agree})
        goods = [t for t in tests if not t.get("error")]
        if agree and goods:
            merged = dict(last)
            merged["mbps"] = statistics.fmean([t["mbps"] for t in goods])
            merged["ping_ms"] = mean_or_none([t["ping_ms"] for t in goods])
            merged["error"] = None
            merged["note"] = "confirmed"
            reps.append(merged)
        elif agree:
            merged = dict(last)
            merged["note"] = "failed twice"
            reps.append(merged)
    return reps, checks


def load_history(since=None):
    con = db()
    try:
        if since:
            return con.execute("SELECT * FROM tests WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
        return con.execute("SELECT * FROM tests ORDER BY ts").fetchall()
    finally:
        con.close()


def is_benchmark_row(row, cfg):
    if row["benchmark"] is not None:
        return bool(row["benchmark"])
    return (row["country"] or "") in benchmark_countries(cfg)


# ---------- presentation ----------

def fmt_dur(seconds):
    if seconds is None:
        return "-"
    s = max(0, int(seconds))
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def fmt_mbps(v):
    return f"{v:6.1f}" if v is not None else "     -"


def fmt_ms(v):
    return f"{v:5.0f}" if v is not None else "    -"


def clip(text, width):
    text = text or ""
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def color(text, code, enabled):
    if not enabled or not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def delta_pct(value, base):
    if value is None or not base:
        return None
    return 100.0 * (value - base) / base


def snapshot(run, rows, bench_countries_list, agree_ratio=0.25):
    rows = [dict(r) for r in rows]
    reps, checks = collapse_rows(rows, agree_ratio)
    bench = [r for r in reps if r.get("benchmark")]
    survey = [r for r in reps if not r.get("benchmark")]

    def ok(rs):
        return [r for r in rs if not r.get("error")]

    raw_ok = [r for r in rows if not r.get("error") and r.get("mbps")]
    se_mbps = median_or_none([r["mbps"] for r in ok(bench)])
    se_ping = median_or_none([r["ping_ms"] for r in ok(bench)])
    na_mbps = median_or_none([r["mbps"] for r in ok(survey)])
    na_ping = median_or_none([r["ping_ms"] for r in ok(survey)])
    fastest = sorted(ok(survey), key=lambda r: r["mbps"] or 0, reverse=True)
    slowest = sorted(survey, key=lambda r: (r["mbps"] or 0))
    fast_hosts = {r["host"] for r in fastest[:6]}
    slowest = [r for r in slowest if r["host"] not in fast_hosts] or slowest
    return {
        "run": dict(run) if run is not None else None,
        "bench": bench,
        "survey": survey,
        "fastest": fastest,
        "slowest": slowest,
        "checks": checks,
        "se_mbps": se_mbps,
        "se_ping": se_ping,
        "na_mbps": na_mbps,
        "na_ping": na_ping,
        "avg_mbps": mean_or_none([r["mbps"] for r in raw_ok]),
        "avg_ping": mean_or_none([r["ping_ms"] for r in raw_ok]),
        "sample_n": len(raw_ok),
        "bench_countries": bench_countries_list,
    }


def result_line(row, se_mbps, width, colored):
    city = clip(row.get("city_name") or row.get("city") or "", 16)
    err = row.get("error")
    if err:
        body = f"{row['host']:<16} {city:<16}  failed  {clip(err, max(8, width - 44))}"
        return color(clip(body, width), "31", colored)
    pct = delta_pct(row.get("mbps"), se_mbps)
    vs = f"{pct:+4.0f}%" if pct is not None else "     "
    extra = ""
    if row.get("note"):
        extra += f"  {row['note']}"
    if row.get("loss_pct"):
        extra += f"  {row['loss_pct']:.0f}% loss"
    ping = row.get("ping_ms")
    body = f"{row['host']:<16} {city:<16} {fmt_mbps(row.get('mbps'))} Mbps {fmt_ms(ping)} ms  {vs}{extra}"
    tone = None
    if pct is not None:
        tone = "32" if pct >= 0 else ("33" if pct >= -15 else "31")
    return color(clip(body, width), tone, colored)


def progress_bar(done, total, width=22):
    if total <= 0:
        return "-" * width
    filled = int(width * min(done, total) / total)
    return "#" * filled + "." * (width - filled)


def dashboard(snap, width, height, colored):
    run = snap["run"] or {}
    planned = run.get("planned") or 0
    tested = run.get("tested") or 0
    title = run.get("title") or "mvbench"
    started = run.get("started")
    elapsed = (datetime.now(timezone.utc) - parse_iso(started)).total_seconds() if started else 0
    remaining = None
    if tested and planned > tested:
        remaining = elapsed / tested * (planned - tested)
    elif planned:
        remaining = max(0, planned - tested) * DEFAULTS["seconds_per_relay"]
    phase = run.get("phase") or ""
    current = run.get("current_host") or ""
    if not (tested >= 1 and elapsed >= 8 and planned > tested):
        remaining = max(0, (planned or 0) - tested) * DEFAULTS["seconds_per_relay"] if planned else None
    working = "  ".join(p for p in (current, phase) if p)
    lines = [
        f"mvbench  {title}",
        f"[{progress_bar(tested, planned)}]  {tested}/{planned or '?'}   {fmt_dur(elapsed)} in   ~{fmt_dur(remaining)} left",
        working or "starting",
        "",
    ]
    se_mbps, se_ping = snap["se_mbps"], snap["se_ping"]
    if se_mbps is None:
        lines.append("Sweden benchmark   (waiting for the first successful test)")
    else:
        ping_bit = f"{se_ping:.0f} ms" if se_ping is not None else "-"
        lines.append(f"Sweden benchmark   median {se_mbps:.0f} Mbps   {ping_bit}   n={len([r for r in snap['bench'] if not r.get('error')])}")
    for row in snap["bench"]:
        lines.append("  " + result_line(row, None, width, colored))
    if not snap["bench"]:
        lines.append("  …")

    def section(heading, rows, limit):
        out = ["", heading]
        if not rows:
            out.append("  …")
            return out
        for i, row in enumerate(rows[:limit], 1):
            prefix = f"{i:>2} " if heading.startswith("Fastest") else "   "
            out.append(prefix + result_line(row, se_mbps, width, colored))
        return out

    # Leave room for the comparison and the slowest list.
    room = max(4, height - len(lines) - 10)
    fast_n = max(3, min(8, room))
    lines += section("Fastest this run", snap["fastest"], fast_n)
    lines += section("Slowest this run", snap["slowest"], 5)
    lines.append("")
    if snap["na_mbps"] is None:
        lines.append("North America   no successful test yet")
    else:
        speed = delta_pct(snap["na_mbps"], se_mbps)
        na_ping = f"{snap['na_ping']:.0f} ms" if snap["na_ping"] is not None else "-"
        ping_bit = ""
        if snap["na_ping"] is not None and se_ping:
            ping_bit = f"   latency {snap['na_ping'] - se_ping:+.0f} ms vs Sweden"
        speed_bit = f"{speed:+.0f}% vs Sweden" if speed is not None else "Sweden benchmark not in yet"
        lines.append(f"North America   median {snap['na_mbps']:.0f} Mbps   {na_ping}   speed {speed_bit}{ping_bit}")
    if snap.get("avg_mbps") is not None:
        ping = f"{snap['avg_ping']:.0f} ms" if snap.get("avg_ping") is not None else "-"
        lines.append(f"all samples   avg {snap['avg_mbps']:.0f} Mbps   {ping}   n={snap['sample_n']}")
    for check in snap.get("checks") or []:
        first, second = check["first"], check["second"]
        verdict = "consistent" if check["agree"] else "fluke, the two tests disagree"
        lines.append(f"retest {first['host']}  {verdict}")
    if run.get("status") and run["status"] != "running":
        lines.append(f"status  {run['status']}")
    restore = run.get("restore")
    if restore and run.get("status") == "running":
        lines.append(f"when finished, relay returns to: {restore}")
    return "\n".join(clip(line, width) if not colored else line for line in lines[: max(1, height)])


def plain_summary(snap):
    run = snap["run"] or {}
    lines = [f"mvbench  {run.get('title') or 'results'}   run {run.get('id') or '-'}   {run.get('status') or ''}"]
    if snap["se_mbps"] is not None:
        se_ping = f"{snap['se_ping']:.0f} ms" if snap["se_ping"] is not None else "-"
        lines.append(f"Sweden benchmark   median {snap['se_mbps']:.0f} Mbps   {se_ping}")
    else:
        lines.append("Sweden benchmark   no successful test")
    for row in snap["bench"]:
        lines.append("  " + result_line(row, None, 100, False))
    lines.append("")
    lines.append("Fastest North America")
    if not snap["fastest"]:
        lines.append("  (none)")
    for i, row in enumerate(snap["fastest"][:8], 1):
        lines.append(f"{i:>2} " + result_line(row, snap["se_mbps"], 100, False))
    lines.append("")
    lines.append("Slowest North America")
    if not snap["slowest"]:
        lines.append("  (none)")
    for row in snap["slowest"][:5]:
        lines.append("   " + result_line(row, snap["se_mbps"], 100, False))
    if snap["na_mbps"] is not None:
        speed = delta_pct(snap["na_mbps"], snap["se_mbps"])
        speed_bit = f", speed {speed:+.0f}% vs Sweden" if speed is not None else ""
        ping_bit = ""
        na_ping = f"{snap['na_ping']:.0f}" if snap["na_ping"] is not None else "-"
        if snap["na_ping"] is not None and snap["se_ping"]:
            ping_bit = f", latency {snap['na_ping'] - snap['se_ping']:+.0f} ms vs Sweden"
        lines.append("")
        lines.append(f"North America median {snap['na_mbps']:.0f} Mbps, {na_ping} ms{speed_bit}{ping_bit}")
    if snap.get("avg_mbps") is not None:
        ping = f"{snap['avg_ping']:.0f}" if snap.get("avg_ping") is not None else "-"
        lines.append(f"all samples this run   avg {snap['avg_mbps']:.0f} Mbps, {ping} ms   n={snap['sample_n']}")
    if snap.get("checks"):
        lines.append("")
        lines.append("Retested because the first result was way off")
        for check in snap["checks"]:
            first, second = check["first"], check["second"]
            verdict = "consistent" if check["agree"] else "not consistent"
            lines.append(f"  {first['host']:<16} {fmt_mbps(first.get('mbps'))} then {fmt_mbps(second.get('mbps'))} Mbps"
                         f"   {fmt_ms(first.get('ping_ms'))} then {fmt_ms(second.get('ping_ms'))} ms   {verdict}")
    return "\n".join(lines)


def draw(snap, colored):
    size = shutil.get_terminal_size((80, 24))
    sys.stdout.write("\033[H" + dashboard(snap, size.columns, size.lines, colored) + "\033[J")
    sys.stdout.flush()


def names_for(relays):
    return {r["host"]: r for r in relays}


def attach_names(rows, relays):
    meta = names_for(relays)
    out = []
    for row in rows:
        item = dict(row)
        known = meta.get(item["host"])
        if known and not item.get("city_name"):
            item["city_name"] = known["city_name"]
        out.append(item)
    return out


# ---------- commands ----------

def cmd_pool(cfg, args):
    survey, bench = pools(cfg)
    print("benchmark")
    for r in bench:
        print(f"  {r['host']:<16} {r['city_name']:<22} {r['provider']:<14} {'owned' if r['owned'] else 'rented'}")
    print(f"\nsurvey  ({', '.join(survey_countries(cfg))})")
    for r in survey:
        print(f"  {r['host']:<16} {r['city_name']:<22} {r['provider']:<14} {'owned' if r['owned'] else 'rented'}")
    print(f"\n{len(bench)} benchmark relays, {len(survey)} survey relays")


def cmd_plan(cfg, args):
    relays = list_relays()
    na_n = args.n if args.n is not None else cfg["relays_per_run"]
    bench_n = args.bench if args.bench is not None else cfg["benchmark_per_run"]
    targets = choose_targets(cfg, relays, na_n, bench_n)
    restore = current_location_args()
    cities = []
    print(f"{scope_title(survey_countries(cfg), benchmark_countries(cfg))}")
    print(f"{len(targets)} relays, about {fmt_dur(len(targets) * cfg['seconds_per_relay'])} at ~{cfg['seconds_per_relay']}s each")
    print(f"restore after: {' '.join(restore) if restore else '(could not parse current constraint)'}\n")
    stats = history_stats()
    for i, (r, is_bench) in enumerate(targets, 1):
        kind = "bench" if is_bench else "survey"
        prior = stats.get(r["host"])
        if prior and prior["avg_ping"] is not None:
            rated = f"avg {prior['avg_mbps']:5.0f} Mbps  {prior['avg_ping']:4.0f} ms  n={prior['n']}"
        else:
            rated = "no history yet"
        print(f"{i:>3}  {kind:<7} {r['host']:<16} {r['country']} {r['city_name']:<18} {rated}")
        if not is_bench:
            cities.append((r["country"], r["city"]))
    covered = len(set(cities))
    survey, _ = pools(cfg, relays)
    total_cities = len({(r["country"], r["city"]) for r in survey})
    print(f"\n{covered}/{total_cities} North America cities in this run")
    print("Best-rated relays are first. Results far from the pack are retested at the end.")


def log_line(i, total, row):
    kind = "retest" if row.get("flag") == "retest" else ("bench" if row["benchmark"] else "survey")
    if row["error"]:
        detail = row["error"]
    else:
        detail = f"{row['mbps']:6.1f} Mbps  {fmt_ms(row['ping_ms'])} ms"
    print(f"[{i}/{total}] {kind:<7} {row['host']:<16} {detail}", flush=True)


def blank_row(relay, is_bench, error=None, flag=None):
    return {
        "host": relay["host"], "city": relay["city"], "city_name": relay["city_name"],
        "country": relay["country"], "provider": relay["provider"], "owned": int(relay["owned"]),
        "benchmark": int(is_bench), "connect_s": None, "ping_ms": None, "jitter_ms": None,
        "loss_pct": None, "mbps": 0.0, "ttfb_s": None, "error": error, "service_fail": None,
        "flag": flag,
    }


def test_one(cfg, relay, is_bench, on_phase=None):
    def phase(name):
        if on_phase:
            on_phase(name)

    row = blank_row(relay, is_bench)
    phase("connect")
    t = connect_to(relay["host"], cfg["connect_timeout"])
    if t is None:
        row["error"] = "connect timeout"
        return row
    row["connect_s"] = t
    time.sleep(cfg["settle_seconds"])
    phase("ping")
    row["ping_ms"], row["jitter_ms"], row["loss_pct"] = measure_ping(cfg["ping_target"], cfg["ping_count"])
    phase("download")
    row["mbps"], row["ttfb_s"], row["error"] = measure_download(cfg["download_urls"], cfg["download_max_time"])
    if cfg["service_checks"]:
        failed = run_service_checks(cfg["service_checks"])
        row["service_fail"] = ", ".join(failed) or None
    return row


def save_test(con, run_id, row):
    con.execute(
        """INSERT INTO tests (
            ts, host, city, city_name, country, provider, owned, benchmark, run_id, flag,
            connect_s, ping_ms, jitter_ms, loss_pct, mbps, ttfb_s, error, service_fail)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (now_iso(), row["host"], row["city"], row["city_name"], row["country"], row["provider"],
         row["owned"], row["benchmark"], run_id, row.get("flag"), row["connect_s"], row["ping_ms"],
         row["jitter_ms"], row["loss_pct"], row["mbps"], row["ttfb_s"], row["error"], row["service_fail"]))
    con.commit()


def set_progress(con, run_id, host, phase, tested):
    con.execute(
        "UPDATE runs SET current_host = ?, phase = ?, tested = ? WHERE id = ?",
        (host, phase, tested, run_id))
    con.commit()


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def acquire_lock():
    if LOCK_PATH.exists():
        raw = LOCK_PATH.read_text().strip()
        if raw.isdigit() and pid_alive(int(raw)):
            sys.exit(f"a run is already going (pid {raw}). Follow it with: ./mvbench.py watch")
    LOCK_PATH.write_text(str(os.getpid()))


def release_lock():
    try:
        if LOCK_PATH.exists() and LOCK_PATH.read_text().strip() == str(os.getpid()):
            LOCK_PATH.unlink()
    except OSError:
        pass


def _stop(_signum, _frame):
    raise KeyboardInterrupt


def cmd_run(cfg, args):
    acquire_lock()
    signal.signal(signal.SIGTERM, _stop)
    try:
        _cmd_run(cfg, args)
    finally:
        release_lock()


def _cmd_run(cfg, args):
    relays = list_relays()
    by_host = {r["host"]: r for r in relays}
    if args.hosts:
        unknown = [h for h in args.hosts if h not in by_host]
        if unknown:
            sys.exit(f"unknown relay(s): {', '.join(unknown)}")
        bench_set = set(benchmark_countries(cfg))
        targets = [(by_host[h], by_host[h]["country"] in bench_set) for h in args.hosts]
    else:
        na_n = args.n if args.n is not None else cfg["relays_per_run"]
        bench_n = args.bench if args.bench is not None else cfg["benchmark_per_run"]
        targets = choose_targets(cfg, relays, na_n, bench_n)
    if not targets:
        sys.exit("no candidate relays (check config.toml / blocklist.txt)")

    restore = current_location_args()
    if restore:
        RESTORE_PATH.write_text(" ".join(restore) + "\n")
    title = scope_title(survey_countries(cfg), benchmark_countries(cfg))
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    con = db()
    con.execute(
        """INSERT INTO runs (id, started, status, planned, tested, phase, scope, title, restore)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, now_iso(), "running", len(targets), 0, "starting",
         ",".join(survey_countries(cfg)) + "|" + ",".join(benchmark_countries(cfg)),
         title, " ".join(restore) if restore else None))
    con.commit()

    use_ui = sys.stdout.isatty() and not args.plain
    print(
        f"run {run_id}  {len(targets)} relays  about {fmt_dur(len(targets) * cfg['seconds_per_relay'])}\n"
        f"tunnel switches until this finishes, then restores: {' '.join(restore) if restore else 'unknown'}\n"
        f"watch it in another terminal:  ./mvbench.py watch",
        flush=True)
    if use_ui:
        sys.stdout.write(ALT_ON)
        sys.stdout.flush()

    status_name = "done"
    prior = history_stats()
    queue = list(targets)
    first_pass = len(queue)
    collected = []

    def show():
        if not use_ui:
            return
        run, rows = fetch_run(run_id)
        draw(snapshot(run, attach_names(rows, relays), benchmark_countries(cfg), cfg["agree_ratio"]), True)

    try:
        i = 0
        while i < len(queue):
            relay, is_bench = queue[i]
            retest = i >= first_pass
            if not use_ui:
                label = "retesting" if retest else "testing"
                print(f"[{i + 1}/{len(queue)}] {label} {relay['host']}…", flush=True)

            def on_phase(name, host=relay["host"], done=i, retest=retest):
                set_progress(con, run_id, host, "retest" if retest else name, done)
                show()

            try:
                row = test_one(cfg, relay, is_bench, on_phase)
            except RuntimeError as exc:
                row = blank_row(relay, is_bench, str(exc))
            row["flag"] = "retest" if retest else None
            save_test(con, run_id, row)
            collected.append(row)
            set_progress(con, run_id, relay["host"], "saved", i + 1)
            show()
            if not use_ui:
                log_line(i + 1, len(queue), row)
            i += 1
            if i == first_pass:
                flagged = select_retests(collected, prior, cfg)
                if flagged:
                    known = {host: (rel, bench) for rel, bench in queue}
                    for _score, row, reason in flagged:
                        con.execute(
                            "UPDATE tests SET flag = ? WHERE run_id = ? AND host = ? AND flag IS NULL",
                            (f"outlier:{reason}", run_id, row["host"]))
                        relay, is_b = known[row["host"]]
                        queue.append((relay, is_b))
                    con.execute("UPDATE runs SET planned = ? WHERE id = ?", (len(queue), run_id))
                    con.commit()
                    names = ", ".join(f"{row['host']} ({reason})" for _s, row, reason in flagged)
                    if use_ui:
                        show()
                    else:
                        print(f"retest {len(flagged)} way-off result(s): {names}", flush=True)
    except KeyboardInterrupt:
        status_name = "interrupted"
        print("\ninterrupted", flush=True)
    except Exception:
        status_name = "error"
        raise
    finally:
        if use_ui:
            sys.stdout.write(ALT_OFF)
            sys.stdout.flush()
        if args.apply and status_name == "done":
            if RESTORE_PATH.exists():
                RESTORE_PATH.unlink()
            cmd_apply(cfg, argparse.Namespace(top=None))
        elif apply_restore(restore):
            print(f"restored relay constraint: {' '.join(restore)}", flush=True)
        else:
            print("could not parse the previous relay constraint; left on the last tested relay", file=sys.stderr)
        con.execute(
            "UPDATE runs SET status = ?, finished = ?, phase = ? WHERE id = ?",
            (status_name, now_iso(), "finished", run_id))
        con.commit()
        run, rows = fetch_run(run_id)
        print()
        print(plain_summary(snapshot(run, attach_names(rows, relays), benchmark_countries(cfg), cfg["agree_ratio"])))


def cmd_watch(cfg, args):
    run_id = args.run
    use_ui = sys.stdout.isatty()
    relays = None
    shown = False
    if use_ui:
        sys.stdout.write(ALT_ON)
        sys.stdout.flush()
    try:
        while True:
            run, rows = fetch_run(run_id)
            if run is None:
                if use_ui:
                    sys.stdout.write(ALT_OFF)
                sys.exit("no runs yet. Start one with: ./mvbench.py run")
            if relays is None:
                try:
                    relays = list_relays()
                except RuntimeError:
                    relays = []
            snap = snapshot(run, attach_names(rows, relays), benchmark_countries(cfg), cfg["agree_ratio"])
            if use_ui:
                draw(snap, True)
            elif not shown or run["status"] == "running":
                sys.stdout.write("\033[H\033[J" + plain_summary(snap) + "\n")
                sys.stdout.flush()
                shown = True
            if run["status"] != "running":
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        if use_ui:
            sys.stdout.write(ALT_OFF)
            sys.stdout.flush()
        print("stopped watching. The run keeps going.  ./mvbench.py watch")
        return
    if use_ui:
        sys.stdout.write(ALT_OFF)
        sys.stdout.flush()
    run, rows = fetch_run(run_id)
    relays = relays or []
    print(plain_summary(snapshot(run, attach_names(rows, relays), benchmark_countries(cfg), cfg["agree_ratio"])))


def summarize_tests(cfg, rows, include_blocked=False):
    blocked, allowed = set(), None
    pats = load_blocklist()
    by_host = {}
    for row in rows:
        if is_blocked(row["host"], pats) and not include_blocked:
            continue
        by_host.setdefault(row["host"], []).append(row)
    stats = []
    for host, tests in by_host.items():
        speeds = [t["mbps"] or 0.0 for t in tests]
        ok = [t for t in tests if not t["error"]]
        pings = [t["ping_ms"] for t in ok if t["ping_ms"] is not None]
        ok_speeds = [t["mbps"] for t in ok if t["mbps"]]
        med, p20 = statistics.median(speeds), percentile(speeds, 0.2)
        mean = statistics.fmean(speeds)
        cv = statistics.pstdev(speeds) / mean if mean > 0 else 0.0
        n = len(tests)
        confidence = min(1.0, n / max(cfg["min_samples"], 1))
        last = tests[-1]
        stats.append({
            "host": host,
            "country": last["country"] or host[:2],
            "city": last["city"],
            "city_name": last["city_name"] or last["city"] or "",
            "provider": last["provider"] or "",
            "owned": bool(last["owned"]),
            "benchmark": is_benchmark_row(last, cfg),
            "n": n,
            "ok_pct": 100 * len(ok) / n,
            "median": med,
            "p20": p20,
            "max": max(speeds),
            "cv": cv,
            "ping": statistics.median(pings) if pings else None,
            "avg_mbps": statistics.fmean(ok_speeds) if ok_speeds else 0.0,
            "avg_ping": statistics.fmean(pings) if pings else None,
            "score": (0.6 * p20 + 0.4 * med) * confidence,
            "last": last["ts"],
            "svc_fail": last["service_fail"],
            "blocked": is_blocked(host, pats),
            "speeds": speeds,
        })
    stats.sort(key=lambda s: s["score"], reverse=True)
    return stats


def trend_label(speeds):
    if len(speeds) < 4:
        return ""
    cut = max(1, len(speeds) // 3)
    older, newer = speeds[:-cut], speeds[-cut:]
    base = statistics.median(older)
    if base <= 0:
        return ""
    change = 100.0 * (statistics.median(newer) - base) / base
    if abs(change) < 8:
        return "flat"
    return f"{change:+.0f}%"


def cmd_report(cfg, args):
    since = (datetime.now(timezone.utc) - timedelta(days=cfg["window_days"])).isoformat()
    rows = load_history(since)
    stats = summarize_tests(cfg, rows, include_blocked=args.all)
    if not stats:
        older = load_history()
        if older:
            sys.exit(f"no tests in the last {cfg['window_days']} days. See older samples with ./mvbench.py patterns")
        sys.exit("no test data yet. Start with ./mvbench.py run")
    bench = [s for s in stats if s["benchmark"]]
    survey = [s for s in stats if not s["benchmark"]]
    print(f"last {cfg['window_days']} days. avg is successful tests only. score = (0.6*p20 + 0.4*median) Mbps, failures count as 0.")
    if bench:
        print(f"\nSweden / benchmark  median {statistics.median([s['median'] for s in bench]):.0f} Mbps")
        print_stats(bench)
    print("\nsurvey")
    print_stats(survey or [])
    if not survey:
        print("  (none)")


def print_stats(stats):
    print(f"{'relay':<16} {'where':<18} {'n':>3} {'avg':>6} {'med':>6} {'avgms':>6} {'medms':>6} {'score':>6}")
    for s in stats:
        where = clip(s["city_name"] or s["city"] or "", 18)
        avg_ping = f"{s['avg_ping']:.0f}" if s.get("avg_ping") is not None else "-"
        med_ping = f"{s['ping']:.0f}" if s["ping"] is not None else "-"
        print(f"{s['host']:<16} {where:<18} {s['n']:>3} {s['avg_mbps']:>6.1f} {s['median']:>6.1f}"
              f" {avg_ping:>6} {med_ping:>6} {s['score']:>6.1f}")


def cmd_patterns(cfg, args):
    rows = [dict(r) for r in load_history()]
    if not rows:
        sys.exit("no test data yet. Start with ./mvbench.py run")
    first, last = rows[0]["ts"][:10], rows[-1]["ts"][:10]
    ok = [r for r in rows if not r.get("error") and r.get("mbps")]
    pings = [r["ping_ms"] for r in ok if r.get("ping_ms") is not None]
    print(f"all stored tests   {len(rows)}   {first} → {last}")
    if ok:
        print(f"overall   avg {statistics.fmean([r['mbps'] for r in ok]):.0f} Mbps"
              f"   avg ping {statistics.fmean(pings):.0f} ms" if pings else
              f"overall   avg {statistics.fmean([r['mbps'] for r in ok]):.0f} Mbps")
        print(f"          median {statistics.median([r['mbps'] for r in ok]):.0f} Mbps"
              f"   median ping {statistics.median(pings):.0f} ms" if pings else "")
    print("Averages ignore failed tests. Trend compares the newest third with the older samples.\n")

    def group(keyfn):
        buckets = {}
        for row in rows:
            buckets.setdefault(keyfn(row), []).append(row)
        return buckets

    print(f"{'country':<10} {'n':>4} {'relays':>6} {'avg':>7} {'med':>7} {'avgms':>6} {'medms':>6} {'trend':>6}  last")
    for country, tests in sorted(group(lambda r: r["country"] or "?").items()):
        speeds = [t["mbps"] or 0.0 for t in tests if not t["error"]]
        pings = [t["ping_ms"] for t in tests if t["ping_ms"] is not None and not t["error"]]
        relays_n = len({t["host"] for t in tests})
        avg_ping = f"{statistics.fmean(pings):.0f}" if pings else "-"
        med_ping = f"{statistics.median(pings):.0f}" if pings else "-"
        avg_mbps = f"{statistics.fmean(speeds):.1f}" if speeds else "-"
        med_mbps = f"{statistics.median(speeds):.1f}" if speeds else "-"
        print(f"{COUNTRY_NAMES.get(country, country):<10} {len(tests):>4} {relays_n:>6} "
              f"{avg_mbps:>7} {med_mbps:>7} {avg_ping:>6} {med_ping:>6} {trend_label(speeds):>6}  {tests[-1]['ts'][:10]}")

    print(f"\n{'city':<22} {'n':>4} {'avg':>7} {'med':>7} {'avgms':>6} {'medms':>6} {'trend':>6}  last")
    city_rows = group(lambda r: (r["country"] or "?", r["city"] or "?"))
    ranked = []
    for (country, city), tests in city_rows.items():
        names = [t["city_name"] for t in tests if t.get("city_name")]
        city_name = max(names, key=len) if names else city
        speeds = [t["mbps"] for t in tests if not t["error"] and t["mbps"]]
        pings = [t["ping_ms"] for t in tests if t["ping_ms"] is not None and not t["error"]]
        ranked.append((statistics.median(speeds) if speeds else 0, country, city_name, tests, speeds, pings))
    for med, country, city_name, tests, speeds, pings in sorted(ranked, reverse=True):
        avg_ping = f"{statistics.fmean(pings):.0f}" if pings else "-"
        med_ping = f"{statistics.median(pings):.0f}" if pings else "-"
        avg_mbps = statistics.fmean(speeds) if speeds else 0
        label = clip(f"{country}/{city_name}", 22)
        print(f"{label:<22} {len(tests):>4} {avg_mbps:>7.1f} {med:>7.1f} "
              f"{avg_ping:>6} {med_ping:>6} {trend_label(speeds):>6}  {tests[-1]['ts'][:10]}")

    print(f"\n{'relay':<16} {'n':>3} {'avg':>7} {'med':>7} {'avgms':>6} {'medms':>6}  recent Mbps")
    relay_rows = group(lambda r: r["host"])
    relay_ranked = []
    for host, tests in relay_rows.items():
        speeds = [t["mbps"] for t in tests if not t["error"] and t["mbps"]]
        pings = [t["ping_ms"] for t in tests if t["ping_ms"] is not None and not t["error"]]
        relay_ranked.append((statistics.median(speeds) if speeds else 0, host, tests, speeds, pings))
    relay_ranked.sort(reverse=True)
    for med, host, tests, speeds, pings in relay_ranked:
        avg_ping = f"{statistics.fmean(pings):.0f}" if pings else "-"
        med_ping = f"{statistics.median(pings):.0f}" if pings else "-"
        avg_mbps = statistics.fmean(speeds) if speeds else 0
        recent = " ".join(f"{s:.0f}" for s in speeds[-4:])
        print(f"{host:<16} {len(speeds):>3} {avg_mbps:>7.1f} {med:>7.1f} {avg_ping:>6} {med_ping:>6}  {recent}")


def eligible(cfg, stats):
    out = []
    for s in stats:
        if s["benchmark"] or s["blocked"] or s["svc_fail"] or s["n"] < cfg["min_samples"]:
            continue
        if cfg["max_ping_ms"] and (s["ping"] is None or s["ping"] > cfg["max_ping_ms"]):
            continue
        out.append(s)
    return out


def best_relays(cfg, limit):
    """Best exits in the recent window, highest average speed first, then lowest ping."""
    since = (datetime.now(timezone.utc) - timedelta(days=cfg["window_days"])).isoformat()
    ranked = []
    for s in summarize_tests(cfg, load_history(since)):
        if s["blocked"] or s["svc_fail"] or not s["avg_mbps"]:
            continue
        if cfg["max_ping_ms"] and (s["ping"] is None or s["ping"] > cfg["max_ping_ms"]):
            continue
        ranked.append(s)
    ranked.sort(key=lambda s: (-s["avg_mbps"], s["ping"] if s["ping"] is not None else 1e9))
    return ranked[:limit]


def cmd_recommend(cfg, args):
    best = best_relays(cfg, args.top or cfg["top_n"])
    if not best:
        sys.exit(f"no successful tests in the last {cfg['window_days']} days")
    print(f"Top {len(best)} from the last {cfg['window_days']} days, best first.")
    print("apply loads this order into the Mullvad client. The client keeps the tunnel")
    print("inside the list and picks among those relays itself. It does not walk the list in order.")
    print_stats(best)


def load_custom_list(name, best):
    existing = {ln.strip() for ln in mv("custom-list", "list").splitlines() if ln.strip()}
    if name in existing:
        mv("relay", "set", "location", best[0]["host"])
        mv("custom-list", "delete", name)
    mv("custom-list", "new", name)
    for s in best:
        mv("custom-list", "edit", "add", name, s["country"], s["city"], s["host"])


def cmd_apply(cfg, args):
    best = best_relays(cfg, args.top or cfg["top_n"])
    if not best:
        print("no successful tests to load into Mullvad", file=sys.stderr)
        return
    name = cfg["custom_list"]
    if args.pin:
        host = best[0]["host"]
        mv("relay", "set", "location", host)
        mv("connect", check=False)
        print(f"pinned to {host}, the top relay")
        return
    load_custom_list(name, best)
    mv("relay", "set", "custom-list", name)
    mv("connect", check=False)
    print(f"custom list '{name}' is the active relay constraint, best first:")
    for i, s in enumerate(best, 1):
        ping = f"{s['ping']:.0f} ms" if s["ping"] is not None else "-"
        print(f"  {i}. {s['host']:<16} {s['avg_mbps']:6.1f} Mbps  {ping}")
    print("Mullvad stays inside this list. It picks among them by its own weights,")
    print("not by this order. To lock only the top relay: ./mvbench.py apply --pin")


def cmd_connect(cfg, args):
    best = best_relays(cfg, 1)
    if not best:
        sys.exit("no successful tests yet")
    host = best[0]["host"]
    t = connect_to(host, cfg["connect_timeout"])
    print(f"connected to {host} ({best[0]['avg_mbps']:.0f} Mbps)" if t else f"failed to connect to {host}")


def cmd_restore(cfg, args):
    if not RESTORE_PATH.exists():
        saved = current_location_args()
        sys.exit("nothing pending to restore" if saved else "no saved relay constraint")
    restore = RESTORE_PATH.read_text().split()
    if apply_restore(restore):
        print(f"restored: {' '.join(restore)}")
    else:
        sys.exit("restore failed")


def cmd_block(cfg, args):
    pats = load_blocklist()
    if args.action == "ls":
        print("\n".join(pats) or "(empty)")
        return
    if not args.patterns:
        sys.exit("give one or more patterns")
    lines = BLOCKLIST_PATH.read_text().splitlines() if BLOCKLIST_PATH.exists() else []
    if args.action == "add":
        for p in args.patterns:
            if p not in pats:
                lines.append(f"{p}  # added {datetime.now():%Y-%m-%d}" + (f" {args.reason}" if args.reason else ""))
    else:
        lines = [ln for ln in lines if ln.split("#", 1)[0].strip() not in args.patterns]
    BLOCKLIST_PATH.write_text("\n".join(lines) + "\n")
    print("\n".join(load_blocklist()) or "(empty)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pool")
    p = sub.add_parser("plan")
    p.add_argument("-n", type=int, help="North America relays to include")
    p.add_argument("--bench", type=int, help="Sweden (benchmark) relays to include")
    p = sub.add_parser("run")
    p.add_argument("-n", type=int, help="North America relays to test")
    p.add_argument("--bench", type=int, help="benchmark relays to test")
    p.add_argument("--plain", action="store_true", help="line log even on a terminal")
    p.add_argument("--apply", action="store_true", help="select the top surveyed custom list when done")
    p.add_argument("hosts", nargs="*")
    p = sub.add_parser("watch")
    p.add_argument("run", nargs="?", help="run id to follow (default: latest)")
    p = sub.add_parser("report")
    p.add_argument("--all", action="store_true", help="include blocked relays")
    sub.add_parser("patterns")
    p = sub.add_parser("recommend")
    p.add_argument("--top", type=int)
    p = sub.add_parser("apply")
    p.add_argument("--top", type=int)
    p.add_argument("--pin", action="store_true", help="use only the top relay instead of the custom list")
    sub.add_parser("connect")
    sub.add_parser("restore")
    p = sub.add_parser("block")
    p.add_argument("action", choices=["add", "rm", "ls"])
    p.add_argument("patterns", nargs="*")
    p.add_argument("--reason", default="")
    args = ap.parse_args()
    cfg = load_config()
    {
        "pool": cmd_pool, "plan": cmd_plan, "run": cmd_run, "watch": cmd_watch,
        "report": cmd_report, "patterns": cmd_patterns, "recommend": cmd_recommend,
        "apply": cmd_apply, "connect": cmd_connect, "restore": cmd_restore, "block": cmd_block,
    }[args.cmd](cfg, args)


if __name__ == "__main__":
    main()
