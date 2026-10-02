#!/usr/bin/env python3
"""Drive the 5 fuzz surfaces for 50K iters / 60s wall-clock cap each.

Per-surface output:
  cycle_160/adversary/logs/<surface>.log        raw stdout+stderr
  cycle_160/adversary/<surface>/stats.json     per-surface stats
  cycle_160/adversary/crashes/<surface>_crash-...   crashes (if any)

Honest-input policy: only report numbers that come out of atheris; never
fabricate.
"""

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FUZZ = ROOT / "fuzz"
CORPUS = ROOT / "corpus"
LOGS = ROOT / "logs"
CRASHES = ROOT / "crashes"
PER_SURFACE_DIR = ROOT   # stats.json per surface live under cycle_160/adversary/<surface>/

SURFACES = (
    "set_cookie_parse",
    "cookie_header_parse",
    "set_cookie_build",
    "invariant21",
    "date_parse",
)

# atheris/libFuzzer terse summary, two real forms seen:
#   "#12345\tDONE   cov: 37 ft: 72 corp: 12/3201b lim: 3000"
#   "#50000\tDONE   cov: 52 ft: 266 corp: 90/30Kb lim: 3000 exec/s: 8333 rss: 43Mb"
# The corp-size suffix is lowercase "b" or uppercase "Kb" (or "Mb").
DONE_RE = re.compile(
    r"#(\d+)\s+DONE\s+.*"
    r"cov:\s+(\d+)\s+"
    r"ft:\s+(\d+)\s+"
    r"corp:\s+(\d+)/(\d+)([bKM]?b)\b"
)


def run_surface(surface: str, runs: int = 50_000, total_time: int = 120,
               timeout_per_input: int = 5) -> dict:
    log_path = LOGS / f"{surface}.log"
    stats_path = PER_SURFACE_DIR / surface / "stats.json"
    stats_path.parent.mkdir(parents=True, exist_ok=True)

    # Snapshot the seed-corpus size BEFORE the run so stats.json reports the
    # hand-authored seed count rather than the post-mutation disk size.
    initial_seeds = [p for p in (CORPUS / surface).iterdir()
                     if p.name.startswith("seed_")]
    corpus_size_initial = len(initial_seeds)

    cmd = [
        sys.executable,
        str(FUZZ / f"{surface}.py"),
        str(CORPUS / surface),
        f"-runs={runs}",
        f"-timeout={timeout_per_input}",
        f"-max_total_time={total_time}",
        f"-artifact_prefix={CRASHES / f'{surface}_'}",
    ]

    started = time.time()
    started_iso = datetime.now(timezone.utc).isoformat()
    with log_path.open("wb") as logf:
        proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT,
                              timeout=total_time + 30, check=False)
    elapsed = time.time() - started
    rc = proc.returncode

    log_text = log_path.read_text(errors="replace")
    iters_total = 0
    cov = ft = corp_cnt = corp_bytes = corp_suffix = None
    for line in log_text.splitlines():
        m = DONE_RE.search(line)
        if m:
            iters_total = int(m.group(1))
            cov = int(m.group(2))
            ft = int(m.group(3))
            corp_cnt = int(m.group(4))
            corp_bytes = int(m.group(5))
            corp_suffix = m.group(6)
            break

    crashes = sorted(p.name for p in CRASHES.glob(f"{surface}_crash-*"))
    hangs = sorted(p.name for p in CRASHES.glob(f"{surface}_hang-*"))
    ooms = sorted(p.name for p in CRASHES.glob(f"{surface}_oom-*"))

    stats = {
        "surface": surface,
        "iters_total": iters_total,
        "iters_per_second": (
            round(iters_total / elapsed, 1) if elapsed > 0 else None
        ),
        "elapsed_seconds": round(elapsed, 1),
        "corpus_size_initial": corpus_size_initial,
        "corpus_size_after": corp_cnt,
        "corpus_size_bytes_after": corp_bytes,
        "corpus_size_suffix": corp_suffix,
        "cov_edges": cov,
        "ft_count": ft,
        "crashes": len(crashes),
        "crash_files": crashes,
        "hangs": len(hangs),
        "hang_files": hangs,
        "ooms": len(ooms),
        "oom_files": ooms,
        "distinct_findings": len(crashes) + len(hangs) + len(ooms),
        "fuzzer_version": "atheris 3.0.0",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "started_at_utc": started_iso,
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "exit_code": rc,
        "runs_requested": runs,
        "max_total_time_s": total_time,
        "timeout_per_input_s": timeout_per_input,
        "log_path": str(log_path),
    }
    stats_path.write_text(json.dumps(stats, indent=2))
    print(
        f"[{surface:>22}] "
        f"iters={stats['iters_total']:>6} "
        f"cov={stats['cov_edges']:>4} "
        f"ft={stats['ft_count']:>4} "
        f"corp={stats['corpus_size_after']:>3}/{stats['corpus_size_bytes_after']}{stats['corpus_size_suffix']} "
        f"crashes={stats['crashes']} "
        f"hangs={stats['hangs']} "
        f"ooms={stats['ooms']} "
        f"elapsed={stats['elapsed_seconds']}s "
        f"exit={stats['exit_code']}"
    )
    return stats


def main() -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    CRASHES.mkdir(parents=True, exist_ok=True)
    print(f"=== T3 fuzzer execution — start {datetime.now(timezone.utc).isoformat()} ===")
    overall = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "surfaces": [],
    }
    for s in SURFACES:
        overall["surfaces"].append(run_surface(s))
    overall["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
    overall["total_iters"] = sum(s["iters_total"] for s in overall["surfaces"])
    overall["total_crashes"] = sum(s["crashes"] for s in overall["surfaces"])
    overall["total_hangs"] = sum(s["hangs"] for s in overall["surfaces"])
    overall["total_ooms"] = sum(s["ooms"] for s in overall["surfaces"])
    overall_path = ROOT / "summary.json"
    overall_path.write_text(json.dumps(overall, indent=2))
    print(
        f"=== T3 DONE — total_iters={overall['total_iters']} "
        f"crashes={overall['total_crashes']} "
        f"hangs={overall['total_hangs']} "
        f"ooms={overall['total_ooms']} ==="
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())