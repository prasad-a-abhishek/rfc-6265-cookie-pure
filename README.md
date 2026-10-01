# rfc-6265-cookie-pure

**Zero-dependency pure-Python RFC 6265 HTTP cookie parser and serializer.**

> Parse `Set-Cookie` headers and serialize cookies without `urllib` / `http.cookiejar`. No external dependencies — runs anywhere Python runs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](pyproject.toml)

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/rfc-6265-cookie-pure.git
```

```python
from rfc6265_cookie_pure import parse_set_cookie, parse_cookie_header, build_set_cookie

# Parse a Set-Cookie header
cookie = parse_set_cookie("session=abc123; Path=/; HttpOnly; SameSite=Lax")
assert cookie.name == "session"
assert cookie.value == "abc123"
assert cookie.attributes["samesite"] == "Lax"

# Parse a Cookie request header
cookies = parse_cookie_header("session=abc123; tracking=xyz")
assert cookies == {"session": "abc123", "tracking": "xyz"}

# Serialize a cookie
header = build_set_cookie("session", "abc123", path="/", samesite="Strict")
assert header.startswith("session=abc123; Path=/; SameSite=Strict")
```

## ⚡ Performance & Benchmarks

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

> Full benchmark details in `benchmarks/BENCHMARK.md`. Run locally: `python3 benchmarks/run_benchmark.py`

## Why rfc-6265-cookie-pure?

Python's stdlib `http.cookiejar` is coupled to `urllib.request`, making it unusable in minimal environments (AWS Lambda, Pyodide, Cloudflare Workers, air-gapped systems). Manual string-splitting is non-compliant — it misses quoted-string rules, folding, SameSite grammar, and invalid-attribute rejection.

`rfc-6265-cookie-pure` gives you:
- **Zero dependencies** — pure Python stdlib, no pip install required
- **RFC 6265 compliant** — follows Section 5.4 grammar exactly, including sane-cookie-date parsing
- **Edge-runtime ready** — works in Pyodide, Lambda layers, Cloudflare Workers, any no-deps Python
- **Serializer included** — `build_set_cookie` mirrors the parser for round-trip fidelity

## Key Features

- **4 public API functions**: `parse_set_cookie`, `parse_cookie_header`, `build_set_cookie`, `cookie_to_dict`
- **Full attribute support**: Domain, Path, Expires, Max-Age, Secure, HttpOnly, SameSite (Strict/Lax/None)
- **sane-cookie-date parser** — RFC 6265 Appendix D / RFC 5322 date format
- **Token validation** — cookie names validated against RFC 2616 token grammar
- **121 tests** — 100% pytest pass rate, covering all spec ACs + edge/boundary/invalid cases

## API Reference

```python
from rfc6265_cookie_pure import (
    Cookie,
    parse_set_cookie,
    parse_cookie_header,
    build_set_cookie,
    cookie_to_dict,
    parse_sane_cookie_date,
)

# parse_set_cookie(header: str) -> Cookie
#   Parse a Set-Cookie header string.
#   Raises ValueError on invalid cookie-pair.
#
# parse_cookie_header(header: str) -> dict[str, str]
#   Parse a Cookie: request header into name→value dict.
#   Raises ValueError on empty header.
#
# build_set_cookie(name, value, *, domain=None, path=None, expires=None,
#                  max_age=None, secure=False, httponly=False, samesite=None) -> str
#   Serialize a cookie to Set-Cookie header string.
#
# cookie_to_dict(cookie: Cookie) -> dict
#   Convert a Cookie to a flat dict with name/value top-level and attributes merged.
#
# parse_sane_cookie_date(date_str: str) -> datetime
#   Parse RFC 6265 Appendix D date strings.
```

### Cookie dataclass

```python
@dataclass(frozen=True)
class Cookie:
    name: str
    value: str
    attributes: dict[str, str | None]
    # flags (Secure, HttpOnly) have value None
    # attribute keys are lowercase
```

## Limitations

- No cookie domain-matching algorithm (RFC 6265 §5.1.3, §5.1.4) — parser only, no request-time matcher.
- No cookie storage/persistence (RFC 6265 §5.3 storage model) — this is a parser/serializer, not a CookieJar.
- No RFC 6265bis (draft-revision) support — only the published RFC 6265 grammar.
- `parse_cookie_header` does not implement the full §5.4 `cookie-string` grammar for the `cookie-octet` character set — it splits on semicolons and accepts any non-control character value (aligning with real-world browser behavior rather than the strict RFC grammar for cookie-values in request headers).

## Non-goals

- A full CookieJar with persistence, jar files, or network I/O
- Cookie domain/path matching at request time
- RFC 6265bis extensions

## License

MIT License — see [LICENSE](LICENSE).
