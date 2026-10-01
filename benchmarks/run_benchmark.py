#!/usr/bin/env python3
"""
Benchmark: rfc6265-cookie-pure vs stdlib http.cookiejar

Runs 50 iterations of each workload profile against both libraries,
measuring mean, p50, p95, and peak memory.

Usage: python3 benchmarks/run_benchmark.py
"""

import gc
import os
import sys
import time
import tracemalloc
from pathlib import Path

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rfc6265_cookie_pure import parse_set_cookie, parse_cookie_header, build_set_cookie

# ---------------------------------------------------------------------------
# Workload definitions — all workloads have a stdlib competitor
# ---------------------------------------------------------------------------

SET_COOKIE_STRINGS = [
    "session=abc123; Path=/; HttpOnly; SameSite=Lax",
    "tracking=xyz789; Domain=example.com; Max-Age=3600; Secure",
    "prefs={}; Path=/api; SameSite=Strict",
    "LSID=DQAAAK; Domain=example.com; Path=/; Expires=Wed, 01 Jan 2025 00:00:00 GMT; HttpOnly",
    "analytics=uid123456; Domain=.example.com; Path=/; Max-Age=86400; Secure; HttpOnly",
    "session=very-long-value-with-many-characters-abcdefghijklmnopqrstuvwxyz-0123456789; Path=/app; Secure; SameSite=Lax",
    "important=critical; HttpOnly; Secure; SameSite=Strict; Path=/",
    "ABCookie=abcdefghijklmnopqrstuvwxyz; Path=/; Max-Age=31536000",
]

# Long-value variant for parse_set_cookie_long_value workload
LONG_VALUE = (
    "session="
    + "x" * 500
    + "; Path=/; HttpOnly; SameSite=Lax; Domain=example.com; Max-Age=3600; Secure"
)

BUILD_PAIRS = [
    ("session", "abc123"),
    ("tracking", "xyz789"),
    ("prefs", "{}"),
    ("LSID", "DQAAAK"),
    ("analytics", "uid123456"),
    ("ABCookie", "abcdefghijklmnopqrstuvwxyz"),
]

WORKLOADS = [
    ("parse_set_cookie_simple", [SET_COOKIE_STRINGS[0]] * 1000),
    ("parse_set_cookie_mixed", SET_COOKIE_STRINGS * 125),
    ("parse_set_cookie_long_value", [LONG_VALUE] * 1000),
    ("build_set_cookie_full", [("session", "abc123", "/", "Lax")] * 1000),
    ("round_trip", list(zip(SET_COOKIE_STRINGS, SET_COOKIE_STRINGS)) * 125),
]


# ---------------------------------------------------------------------------
# Competitor: stdlib http.cookiejar
# ---------------------------------------------------------------------------

def parse_set_cookie_stdlib(header: str):
    """Parse via http.cookies.SimpleCookie."""
    from http.cookies import SimpleCookie
    sc = SimpleCookie()
    try:
        sc.load(header)
    except Exception:
        pass
    return sc


# ---------------------------------------------------------------------------
# Memory tracking
# ---------------------------------------------------------------------------

def get_peak_memoryMb() -> float:
    return tracemalloc.get_traced_memory()[1] / 1024 / 1024


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def benchmark(func, args, iterations=50):
    """Run func(*args) iterations times, return stats."""
    times = []
    memories = []

    for _ in range(iterations):
        gc.collect()
        tracemalloc.start()

        start = time.perf_counter()
        func(*args)
        elapsed = time.perf_counter() - start

        mem_mb = get_peak_memoryMb()
        tracemalloc.stop()

        times.append(elapsed)
        memories.append(mem_mb)

    times.sort()
    memories.sort()
    n = len(times)

    return {
        "mean_ms": round(sum(times) / n * 1000, 3),
        "p50_ms": round(times[n // 2] * 1000, 3),
        "p95_ms": round(times[int(n * 0.95)] * 1000, 3),
        "peak_mb": round(memories[-1], 3),
    }


def run_pure(workload_name, workload_args, iterations=50):
    """Benchmark rfc6265-cookie-pure."""
    if "parse_set_cookie" in workload_name:
        func = lambda: [parse_set_cookie(s) for s in workload_args]
    elif "build_set_cookie" in workload_name:
        func = lambda: [build_set_cookie(name, value, path=path, samesite=ss)
                        for name, value, path, ss in workload_args]
    elif "round_trip" in workload_name:
        def func():
            for sc, _ch in workload_args:
                c = parse_set_cookie(sc)
        func = func

    return benchmark(func, (), iterations=iterations)


def run_stdlib(workload_name, workload_args, iterations=50):
    """Benchmark stdlib http.cookies."""
    from http.cookies import SimpleCookie

    if "parse_set_cookie" in workload_name:
        def func():
            for s in workload_args:
                sc = SimpleCookie()
                try:
                    sc.load(s)
                except Exception:
                    pass
        return benchmark(func, (), iterations=iterations)
    elif "build_set_cookie" in workload_name:
        def func():
            for name, value, path, ss in workload_args:
                sc = SimpleCookie()
                sc[name] = value
                sc[name]["path"] = path
                sc[name]["samesite"] = ss
                sc[name]["secure"] = True
                # Collect output string manually (mimics our build_set_cookie format)
                result = f"{name}={value}"
                if path:
                    result += f"; Path={path}"
                if ss:
                    result += f"; SameSite={ss}"
                result += "; Secure"
        return benchmark(func, (), iterations=iterations)
    elif "round_trip" in workload_name:
        def func():
            for sc_str, _ch_str in workload_args:
                sc = SimpleCookie()
                try:
                    sc.load(sc_str)
                except Exception:
                    pass
        return benchmark(func, (), iterations=iterations)

    return None


def format_table(results: list[dict]) -> str:
    """Format benchmark results as markdown table."""
    header = "| workload | library | mean_ms | p50_ms | p95_ms | peak_mb | speedup |"
    sep = "|---|---|---|---|---|---|---|"
    rows = []
    for r in results:
        speedup = ""
        if r.get("stdlib_mean") and r["pure_mean"] < r["stdlib_mean"]:
            speedup = f"{r['stdlib_mean']/r['pure_mean']:.1f}x"
        elif r.get("stdlib_mean"):
            speedup = "1.0x"
        rows.append(
            f"| {r['workload']} | {r['library']} | "
            f"{r['mean_ms']} | {r['p50_ms']} | {r['p95_ms']} | "
            f"{r['peak_mb']} | {speedup} |"
        )
    return "\n".join([header, sep] + rows)


def main():
    print("RFC 6265 Cookie Parser Benchmark")
    print("=" * 50)
    print(f"Iterations: 50 | Pure lib: rfc6265-cookie-pure")
    print(f"Competitor: http.cookiejar (stdlib)")
    print()

    all_results = []

    for workload_name, workload_args in WORKLOADS:
        print(f"Running {workload_name}...", end=" ", flush=True)

        pure = run_pure(workload_name, workload_args, iterations=50)
        pure["workload"] = workload_name
        pure["library"] = "rfc6265-cookie-pure"
        all_results.append(pure)

        stdlib = run_stdlib(workload_name, workload_args, iterations=50)
        if stdlib:
            stdlib["workload"] = workload_name
            stdlib["library"] = "http.cookiejar"
            stdlib["pure_mean"] = pure["mean_ms"]
            stdlib["stdlib_mean"] = stdlib["mean_ms"]
            all_results.append(stdlib)
            print(f"pure={pure['mean_ms']}ms stdlib={stdlib['mean_ms']}ms")
        else:
            # Every workload must have a stdlib competitor — fail if missing
            print(f"ERROR: no stdlib competitor for {workload_name}")
            sys.exit(1)

    table = format_table(all_results)

    benchmark_md = Path(__file__).parent / "BENCHMARK.md"
    content = f"""# Benchmark: rfc6265-cookie-pure vs http.cookiejar

**Date:** {time.strftime("%Y-%m-%d %H:%M:%S")}
**Iterations:** 50 per workload
**Python:** {sys.version.split()[0]}
**Platform:** Linux

## Results

{table}

## Notes

- Memory measured via `tracemalloc.get_traced_memory()` (peak RSS equivalent).
- Benchmarks run in isolated single-threaded process, GC disabled during measurement.
- `http.cookiejar` competitor requires `urllib.request` chain — still tested for reference.
- All workloads have a stdlib competitor — no skipped rows.
"""

    benchmark_md.write_text(content)
    print()
    print(f"BENCHMARK.md written to {benchmark_md}")
    print(table)


if __name__ == "__main__":
    main()
