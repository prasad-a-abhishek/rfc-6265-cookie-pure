"""Regression test: README.md benchmark table must match benchmarks/BENCHMARK.md exactly.

F-CRIT-1 mitigation — prevents README benchmark drift after final benchmark run.
"""
import re


def _parse_benchmark_table(path: str) -> dict[tuple[str, str], dict[str, str]]:
    """Parse a benchmark markdown table into a structured dict.

    Returns: {(workload, library): {metric: value, ...}, ...}
    """
    with open(path) as fh:
        content = fh.read()

    results = {}
    # Match table rows like: | parse_set_cookie_simple | rfc6265-cookie-pure | 31.224 | 31.077 | 32.192 | 0.437 |  |
    row_pattern = re.compile(
        r'^\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|\s*([^\|]*?)\s*\|',
        re.MULTILINE,
    )
    for m in row_pattern.finditer(content):
        workload = m.group(1).strip()
        library = m.group(2).strip()
        mean_ms = m.group(3).strip()
        p50_ms = m.group(4).strip()
        p95_ms = m.group(5).strip()
        peak_mb = m.group(6).strip()
        speedup = m.group(7).strip()
        results[(workload, library)] = {
            "mean_ms": mean_ms,
            "p50_ms": p50_ms,
            "p95_ms": p95_ms,
            "peak_mb": peak_mb,
            "speedup": speedup,
        }
    return results


def test_readme_bench_matches_benchmark():
    """README benchmark table values must EXACTLY match benchmarks/BENCHMARK.md.

    This guards against the builder copying pre-run numbers into README before
    the final benchmark overwrites BENCHMARK.md with fresh numbers.
    """
    import pathlib

    repo_root = pathlib.Path(__file__).parent.parent
    bench_path = repo_root / "benchmarks" / "BENCHMARK.md"
    readme_path = repo_root / "README.md"

    bench_data = _parse_benchmark_table(str(bench_path))
    readme_data = _parse_benchmark_table(str(readme_path))

    assert bench_data, "benchmarks/BENCHMARK.md table is empty or not found"
    assert readme_data, "README.md benchmark table is empty or not found"

    # All workloads in BENCHMARK.md must be present in README
    bench_keys = set(bench_data.keys())
    readme_keys = set(readme_data.keys())

    assert bench_keys == readme_keys, (
        f"Workload/library keys differ:\n"
        f"  only in BENCHMARK.md: {bench_keys - readme_keys}\n"
        f"  only in README.md:   {readme_keys - bench_keys}"
    )

    mismatches = []
    for key in bench_keys:
        bench_row = bench_data[key]
        readme_row = readme_data[key]
        for metric in ["mean_ms", "p50_ms", "p95_ms", "peak_mb", "speedup"]:
            bench_val = bench_row[metric]
            readme_val = readme_row[metric]
            if bench_val != readme_val:
                mismatches.append(
                    f"  {key[0]} | {key[1]} | {metric}: "
                    f"README={readme_val} BENCHMARK={bench_val}"
                )

    assert not mismatches, (
        "F-CRIT-1 regression: README.md benchmark values do not match "
        "benchmarks/BENCHMARK.md:\n" + "\n".join(mismatches)
    )
