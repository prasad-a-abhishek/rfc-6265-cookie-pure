# QA Report — rfc-6265-cookie-pure v0.1.0 (cycle 160)

## Summary

The implementation correctly covers all 4 public APIs and RFC 6265 §5.4 grammar. 121/121 tests pass in a fresh venv. Adversarial fuzzing (14 probes) reveals no crash or correctness bugs — the library handles malformed input gracefully. However, two critical honesty violations block SHIP: (1) the README benchmark table does not match the on-disk BENCHMARK.md, and (2) the pre-push gate lacks the execute bit. One HIGH finding: the README install URL points to a GitHub repo that doesn't exist yet (404).

## Test results

- Tests total: 121 (pytest --collect-only confirmed)
- Tests passed: 121 (fresh-venv, 0 failures)
- Tests failed: 0
- Coverage gaps: None identified — all spec acceptance criteria have ≥1 test

## Adversarial findings

### Critical (block SHIP)

- **F-CRIT-1 — README.md vs BENCHMARK.md benchmark numbers MISMATCH**
  - File: README.md:36-48 vs benchmarks/BENCHMARK.md:12-21
  - All 5 workloads show different mean_ms/p50_ms/p95_ms values between the two files
  - Example: `parse_set_cookie_simple` — README mean=30.808, BENCHMARK.md mean=31.224 (fresh-run)
  - Root cause: builder copied pre-run numbers into README before the final benchmark overwrote BENCHMARK.md with fresh numbers
  - Violates: Honest pillar — "README claims match on-disk reality; benchmarks match BENCHMARK.md"
  - Reproduction: `python3 benchmarks/run_benchmark.py` then compare tables
  - Proposed fix: Update README.md table to match current BENCHMARK.md values, OR regenerate both from the same run

- **F-CRIT-2 — Pre-push gate missing execute bit (mode 0o100600)**
  - File: `.pre-push-gate.sh` (mode 0o100600 — owner-read-write only)
  - Not executable by owner, group, or others
  - Invariant 23 (cycle_159 pattern): "pre-push gate must be executable (mode 755 or 0755)"
  - Impact: `git push` pre-push hook will silently fail to run the gate if `core.hooksPath` points here
  - Reproduction: `stat .pre-push-gate.sh` → Mode: 0o100600; `bash .pre-push-gate.sh` → Permission denied
  - Proposed fix: `chmod 755 .pre-push-gate.sh`

### High (should fix)

- **F-HIGH-1 — README install URL returns HTTP 404 (repo not yet pushed)**
  - File: `README.md:13`
  - URL: `https://github.com/prasad-a-abhishek/rfc-6265-cookie-pure.git` → HTTP 404
  - This is a shipper concern (URL must point to a real repo at push time), but the README documents a non-working command
  - Impact: A user copying the install command gets "remote not found"
  - Reproduction: `curl -s -o /dev/null -w "%{http_code}" "https://github.com/prasad-a-abhishek/rfc-6265-cookie-pure"` → 404
  - Proposed fix (shipper): Replace URL with actual pushed repo URL before publishing

### Medium / Low (informational)

- **F-MED-1 — Malformed expires dates stored raw, not rejected**
  - `parse_set_cookie("session=val; Expires=not-a-date")` accepts and stores the raw string
  - RFC 6265 §5.4 defines `expires-av = "Expires=" sane-cookie-date`; sane-cookie-date is RFC 5322 format
  - Defensive argument: rejecting would drop valid cookies; library is a parser not a validator
  - Note: `parse_sane_cookie_date()` itself correctly rejects invalid dates (F14-DATE-31 Feb 2026 → ValueError)
  - Severity: Medium — spec language suggests non-compliant dates should be rejected; real-world practice is forgiving

- **F-MED-2 — SameSite=None accepted without Secure flag**
  - `parse_set_cookie("session=val; SameSite=None")` accepts without Secure
  - Modern browsers (Chrome, Firefox) reject SameSite=None without Secure
  - RFC 6265 is silent on this combination; the spec does not forbid it
  - Severity: Medium — the library follows the RFC spec letter; real-world interop is the concern

- **F-INFO-1 — Year 0000 date normalized to 2000 (edge case)**
  - `parse_sane_cookie_date("01 Jan 0000 00:00:00")` → year 2000 (via 0→2000 normalization)
  - 2-digit year logic: 0-69 → +2000, 70-99 → +1900
  - Year 0000 falls in the "0-69" bucket
  - Not a bug per se, but worth documenting

- **F-INFO-2 — Negative Max-Age stored as-is**
  - `parse_set_cookie("session=val; Max-Age=-1")` stores raw `max-age=-1`
  - RFC 6265 §5.2.2: "If the max-age attribute value is a non-zero-digit sequence ... A max-age attribute with value "0" ... indicates that the cookie is already expired"
  - Implementation stores raw; caller is responsible for interpreting semantics
  - Not a correctness bug

## Spec compliance

- [x] **RFC 6265 §5.4 grammar** — cookie-pair, cookie-av (Expires, Max-Age, Domain, Path, Secure, HttpOnly, SameSite, extension-av), sane-cookie-date
- [x] **parse_set_cookie(header) -> Cookie** — tested, works
- [x] **parse_cookie_header(header) -> Dict[str, str]** — tested, works
- [x] **build_set_cookie(name, value, **attrs) -> str** — tested, works
- [x] **cookie_to_dict(cookie) -> dict** — tested, works
- [x] **parse_sane_cookie_date** — tested, RFC 5322 date parsing works
- [x] **Cookie dataclass** (frozen=True, lowercase attribute keys) — implemented per spec
- [x] **4 public API functions** per README API Reference — all exported
- [x] **Zero runtime dependencies** (`dependencies = []` in pyproject.toml) — verified
- [x] **121 tests, ≥100 floor** — confirmed via `pytest --collect-only`
- [x] **src LOC ≤ 600** — 413 src LOC + 731 test LOC = 1144 total (within budget)
- [x] **Limitations section** in README (cookiejar, domain-matching, RFC 6265bis) — present
- [x] **Non-goals section** in README — present
- [x] **Competitors named**: `http.cookiejar` (urllib-coupled), `http.cookies` (simple parser) — README §Why rfc-6265-cookie-pure

## Smoke verification

- [x] `pip install -e .` works clean (fresh venv, zero pip errors)
- [x] `pytest tests/ -q` → 121 passed, exit 0
- [x] CLI --help N/A (no CLI — library only)
- [x] End-to-end smoke on real input: parse_set_cookie, parse_cookie_header, build_set_cookie all produce expected output
- [x] No files committed outside /root/projects/rfc-6265-cookie-pure/
- [x] README install instructions: command present but URL is 404 (pre-push/ship finding)

## Adversarial fuzzing (14 probes run)

| Probe | Input | Result |
|---|---|---|
| F1 | Cookie name 10,000 'A's | ACCEPTED — valid token (RFC 6265 allows arbitrary-length tokens) |
| F2 | Lone surrogate \uD800 in value | ACCEPTED — Python str can hold it |
| F3 | Expires=not-a-date | ACCEPTED (stored raw) — MEDIUM concern |
| F4 | SameSite=None without Secure | ACCEPTED — MEDIUM concern |
| F5 | Empty cookie name (=value) | RAISED ValueError — correct |
| F6 | Max-Age=-1 | ACCEPTED (stored raw) — INFO |
| F7 | Duplicate Path= (last wins) | ACCEPTED — correct dict semantics |
| F8 | Path= (empty) | ACCEPTED → '/' — correct per RFC 6265 |
| F9 | Space in cookie name | RAISED ValueError — correct token validation |
| F10 | 100KB cookie value | ACCEPTED — no crash |
| F11 | Null byte in value | ACCEPTED — no crash |
| F12 | Spaces around Cookie header values | ACCEPTED — correct |
| F13 | build_set_cookie with invalid token name | RAISED ValueError — correct |
| F14 | RFC 1123 date edge cases (epoch, 2038, Feb 31, year 0, hour 25) | Correctly accepted/rejected per spec |

## Risk callouts

- **F-CRIT-1 (benchmark mismatch)** MUST be resolved before SHIP. Fresh numbers from `run_benchmark.py` must be copied to README.md. Alternatively, remove the benchmark table from README and keep it only in BENCHMARK.md.
- **F-CRIT-2 (pre-push gate not executable)** MUST be fixed before SHIP. `chmod 755 .pre-push-gate.sh` is a one-liner.
- **F-HIGH-1 (404 install URL)** is a shipper responsibility. The shipper must replace the URL with the real pushed repo URL before publishing.

## Verdict

Two critical findings block SHIP: (1) README benchmark table is stale and does not match on-disk BENCHMARK.md (Honest pillar), and (2) pre-push gate lacks execute bit (Invariant 23). All tests pass and no crash bugs were found. The build is otherwise solid — fix the two criticals and re-run QA for a clean SHIP.

---

VERDICT: FIX
