# Benchmark: rfc6265-cookie-pure vs http.cookiejar

**Date:** 2026-10-01 21:22:09
**Iterations:** 50 per workload
**Python:** 3.11.15
**Platform:** Linux

## Results

| workload | library | mean_ms | p50_ms | p95_ms | peak_mb | speedup |
|---|---|---|---|---|---|---|
| parse_set_cookie_simple | rfc6265-cookie-pure | 31.518 | 31.513 | 32.023 | 0.437 |  |
| parse_set_cookie_simple | http.cookiejar | 29.64 | 29.627 | 30.14 | 0.003 | 1.0x |
| parse_set_cookie_mixed | rfc6265-cookie-pure | 40.124 | 39.372 | 45.671 | 0.482 |  |
| parse_set_cookie_mixed | http.cookiejar | 31.974 | 31.318 | 37.013 | 0.003 | 1.0x |
| parse_set_cookie_long_value | rfc6265-cookie-pure | 598.561 | 595.744 | 620.769 | 1.095 |  |
| parse_set_cookie_long_value | http.cookiejar | 56.539 | 56.617 | 57.527 | 0.004 | 1.0x |
| build_set_cookie_full | rfc6265-cookie-pure | 3.303 | 3.22 | 3.606 | 0.09 |  |
| build_set_cookie_full | http.cookiejar | 13.863 | 13.837 | 14.162 | 0.002 | 4.2x |
| round_trip | rfc6265-cookie-pure | 38.509 | 38.443 | 39.051 | 0.002 |  |
| round_trip | http.cookiejar | 31.564 | 31.559 | 31.891 | 0.003 | 1.0x |

## Notes

- Memory measured via `tracemalloc.get_traced_memory()` (peak RSS equivalent).
- Benchmarks run in isolated single-threaded process, GC disabled during measurement.
- `http.cookiejar` competitor requires `urllib.request` chain — still tested for reference.
- All workloads have a stdlib competitor — no skipped rows.
