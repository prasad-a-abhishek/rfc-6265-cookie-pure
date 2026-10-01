# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 — 2024-10-01 — initial release

- First release: zero-dependency pure-Python RFC 6265 HTTP cookie parser and serializer
- `parse_set_cookie()` — parse Set-Cookie header strings
- `parse_cookie_header()` — parse Cookie request header strings
- `build_set_cookie()` — serialize cookie to Set-Cookie header format
- `cookie_to_dict()` — convenience conversion to flat dict
- `parse_sane_cookie_date()` — RFC 6265 Appendix D date parsing
- 121 tests covering all spec ACs + edge/boundary/invalid cases
- No external dependencies (pure Python stdlib only)
