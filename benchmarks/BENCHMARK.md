# Benchmark: rfc6265-cookie-pure vs http.cookiejar

**Date:** 2026-10-01 21:17:53
**Iterations:** 50 per workload
**Python:** 3.11.15
**Platform:** Linux

## Results

| workload | library | mean_ms | p50_ms | p95_ms | peak_mb | speedup |
|---|---|---|---|---|---|---|
| parse_set_cookie_simple | rfc6265-cookie-pure | 30.808 | 30.739 | 31.529 | 0.437 |  |
| parse_set_cookie_simple | http.cookiejar | 29.011 | 28.923 | 29.723 | 0.003 | 1.0x |
| parse_set_cookie_mixed | rfc6265-cookie-pure | 38.76 | 38.704 | 39.531 | 0.482 |  |
| parse_set_cookie_mixed | http.cookiejar | 31.249 | 30.924 | 32.849 | 0.003 | 1.0x |
| parse_set_cookie_long_value | rfc6265-cookie-pure | 590.748 | 591.825 | 595.769 | 1.095 |  |
| parse_set_cookie_long_value | http.cookiejar | 56.183 | 56.115 | 57.49 | 0.004 | 1.0x |
| build_set_cookie_full | rfc6265-cookie-pure | 3.208 | 3.211 | 3.24 | 0.09 |  |
| build_set_cookie_full | http.cookiejar | 13.748 | 13.719 | 14.226 | 0.002 | 4.3x |
| round_trip | rfc6265-cookie-pure | 38.207 | 38.229 | 38.619 | 0.002 |  |
| round_trip | http.cookiejar | 31.551 | 31.48 | 32.157 | 0.003 | 1.0x |

## Notes

- Memory measured via `tracemalloc.get_traced_memory()` (peak RSS equivalent).
- Benchmarks run in isolated single-threaded process, GC disabled during measurement.
- `http.cookiejar` competitor requires `urllib.request` chain — still tested for reference.
- All workloads have a stdlib competitor — no skipped rows.
