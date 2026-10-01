# Benchmark: rfc6265-cookie-pure vs http.cookiejar

**Date:** 2026-10-01 21:23:54
**Iterations:** 50 per workload
**Python:** 3.11.15
**Platform:** Linux

## Results

| workload | library | mean_ms | p50_ms | p95_ms | peak_mb | speedup |
|---|---|---|---|---|---|---|
| parse_set_cookie_simple | rfc6265-cookie-pure | 31.224 | 31.077 | 32.192 | 0.437 |  |
| parse_set_cookie_simple | http.cookiejar | 29.621 | 29.553 | 30.18 | 0.003 | 1.0x |
| parse_set_cookie_mixed | rfc6265-cookie-pure | 39.111 | 39.02 | 39.824 | 0.482 |  |
| parse_set_cookie_mixed | http.cookiejar | 31.291 | 31.254 | 31.808 | 0.003 | 1.0x |
| parse_set_cookie_long_value | rfc6265-cookie-pure | 596.646 | 596.18 | 605.071 | 1.095 |  |
| parse_set_cookie_long_value | http.cookiejar | 57.548 | 57.67 | 58.24 | 0.004 | 1.0x |
| build_set_cookie_full | rfc6265-cookie-pure | 3.219 | 3.206 | 3.308 | 0.09 |  |
| build_set_cookie_full | http.cookiejar | 13.818 | 13.821 | 14.035 | 0.002 | 4.3x |
| round_trip | rfc6265-cookie-pure | 38.495 | 38.437 | 39.042 | 0.002 |  |
| round_trip | http.cookiejar | 31.889 | 31.807 | 32.525 | 0.003 | 1.0x |

## Notes

- Memory measured via `tracemalloc.get_traced_memory()` (peak RSS equivalent).
- Benchmarks run in isolated single-threaded process, GC disabled during measurement.
- `http.cookiejar` competitor requires `urllib.request` chain — still tested for reference.
- All workloads have a stdlib competitor — no skipped rows.
