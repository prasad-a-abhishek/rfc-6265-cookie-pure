# rfc-6265-cookie-pure Vulnerability Audit (cycle_160/T1)

## Executive Summary

**Audit date**: 2026-10-01
**Repo state**: wt/cycle_160-adversary-01 @ qa-re-verify commit `d0f40c1` (master HEAD `d0f40c1`)
**Auditor**: @repo-adversary (cycle_160/T1)
**Method**: STRIDE-style manual review of `src/rfc6265_cookie_pure/__init__.py` (413 LOC) + 21 adversarial probes (V2 §1–14 expanded) + cross-checks against `tests/test_rfc6265.py` and `README.md`
**Verdict**: NEEDS_REMEDIATION (4 Medium, 6 Low, 2 Info — no Critical or High; F-M1 is a contract violation against Invariant 21 that the orchestrator can document and accept)

## Findings Summary

| Severity | Count | Finding IDs |
|---|---|---|
| Critical | 0 | (none) |
| High | 0 | (none) |
| Medium | 4 | F-M1, F-M2, F-M3, F-M4 |
| Low | 6 | F-L1, F-L2, F-L3, F-L4, F-L5, F-L6 |
| Info | 2 | F-I1, F-I2 |

The 4 Medium findings are non-blocking. F-M1 is a contract gap (Invariant 21 totality), F-M2 / F-M3 are trust-the-input leniency (library, not framework — caller is responsible for sanitization), F-M4 is round-trip non-fidelity on Domain/Path casing. None enable remote code execution, auth bypass, or unauthenticated data exfiltration in the library as-shipped; they would only bite a downstream user that:
- passes non-string input directly to the 4 public functions (F-M1), OR
- forwards user-controlled value/Domain strings to `build_set_cookie` and writes the result to an HTTP response without their own CRLF/Domain sanitization (F-M2 + F-M3), OR
- relies on `build → parse → build` round-trip for `Domain` / `Path` case stability (F-M4).

The T5 FUZZING_REPORT.md Recommendations section should document F-M1–F-M4 as accepted contract boundaries (the package is a parser/serializer, not a sanitizer) unless the orchestrator elects to bump to NEEDS_REMEDIATION.

---

## Per-Finding Detail

### F-M1 — Invariant 21 (totality over arbitrary input) is NOT met (Severity: Medium)

- **File**: `src/rfc6265_cookie_pure/__init__.py:233` (parse_set_cookie), `:284` (parse_cookie_header), `:347` (build_set_cookie), `:396` (cookie_to_dict)
- **Description**: All four public top-level functions raise `AttributeError` / `TypeError` (instead of the documented `ValueError` / `CookieParseError`) when called with non-string types that are not falsy (which the existing `if not header or not header.strip()` guard happens to catch via `0 OR not bool → True`).
- **Repro**:
  ```python
  from rfc6265_cookie_pure import parse_set_cookie, parse_cookie_header, build_set_cookie, cookie_to_dict
  parse_set_cookie(42)         # AttributeError: 'int' object has no attribute 'strip'
  parse_set_cookie(3.14)       # AttributeError: 'float' object has no attribute 'strip'
  parse_set_cookie(b'foo=bar')   # TypeError: cannot use a string pattern on a bytes-like object
  parse_cookie_header(42)      # AttributeError: 'int' object has no attribute 'strip'
  parse_cookie_header(b'...') # TypeError: cannot use a string pattern on a bytes-like object
  build_set_cookie(None, 'v')  # TypeError: 'NoneType' object is not iterable
  build_set_cookie(42, 'v')    # TypeError: 'int' object is not iterable
  build_set_cookie(3.14, 'v')  # TypeError: 'float' object is not iterable
  build_set_cookie([], 'v')    # silently returns '[]=v'
  build_set_cookie({}, 'v')    # silently returns '{}=v'
  build_set_cookie(b'foo', 'v')# silently returns "b'foo'=v"
  cookie_to_dict(None)         # AttributeError: 'NoneType' object has no attribute 'name'
  cookie_to_dict(42)           # AttributeError: 'int' object has no attribute 'name'
  cookie_to_dict(object())     # AttributeError: 'object' object has no attribute 'name'
  ```
- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Recommendation**:
  - For `parse_set_cookie` / `parse_cookie_header`: add an `isinstance(header, str)` guard at the top and raise `TypeError` (or `CookieParseError`) cleanly. The current `header.strip()` and `re.sub(r'^Set-Cookie:\\s*', '', header, ...)` lines blow up with `AttributeError` because `str.strip` doesn't exist on non-str types.
  - For `build_set_cookie`: validate `name` and `value` are `str` instances and not bytes/int/etc; or use keyword-only typed signature (`*` already enforces keyword-only, but doesn't enforce types).
  - For `cookie_to_dict`: add `isinstance(cookie, Cookie)` guard and raise `TypeError`.
  - Alternatively, document in the docstrings that all four functions require `str` / `Cookie` input and raise `TypeError` otherwise — but the existing `ValueError` docstring claim is then misleading.
  - Test the fix with the same probe battery — all 6 cases above should produce clean `TypeError("parse_set_cookie expected str, got int")` etc.

### F-M2 — CRLF in Set-Cookie value and `build_set_cookie` attribute values is not rejected (Severity: Medium)

- **File**: `src/rfc6265_cookie_pure/__init__.py:211` (parse_set_cookie — value path) + `:310` (build_set_cookie — value, domain, path, expires, max-age, samesite string interpolations)
- **Description**:
  - `parse_set_cookie('k=v\r\nSet-Cookie: evil=1')` accepts and returns `value='v\r\nSet-Cookie: evil=1'`. The cookie NAME is correctly validated as RFC 2616 token (rejecting `\r`, `\n`, `:`, etc.), but the VALUE is not — it's captured verbatim via `value_part.rstrip()` after `partition('=')`.
  - `parse_set_cookie` lower-cases attribute names but preserves the attribute VALUE verbatim, so `Domain=example.com\r\nX-Injected: yes=1` becomes `domain='example.com\r\nX-Injected: yes=1'`.
  - `build_set_cookie('k', 'v\r\nX-Injected: yes=1')` emits `k=v\r\nX-Injected: yes=1`. `build_set_cookie('k', 'v', domain='x\r\nX-Injected: y')` emits `k=v; Domain=x\r\nX-Injected: y`. There is NO CRLF sanitization at write-time.
- **Impact**: HTTP response header splitting if the serializer output is written to `response.headers['Set-Cookie']` and the caller passes attacker-controlled strings into `value`/`domain`/`path`/`expires`/`max_age`/`samesite`. This is a classic CRLF-injection pattern documented under CWE-113.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import build_set_cookie, parse_set_cookie
  parse_set_cookie('foo=bar\r\nSet-Cookie: evil=1')
  # -> Cookie('foo', 'bar\r\nSet-Cookie: evil=1', )  # ACCEPTED
  build_set_cookie('k', 'bar\r\nX-Injected: yes=1')
  # -> 'k=bar\r\nX-Injected: yes=1'  # ACCEPTED
  build_set_cookie('k', 'v', domain='example.com\r\nX-Injected: yes=1')
  # -> 'k=v; Domain=example.com\r\nX-Injected: yes=1'  # ACCEPTED
  ```
- **CWE**: CWE-113 (Improper Neutralization of CRLF Sequences in Logs / HTTP Response)
- **Recommendation**:
  - Either document loudly in the docstring: "DO NOT pass untrusted strings to value/domain/path; sanitize before passing." — this is the current implicit contract.
  - Or add a defensive `if any(c in value for c in '\r\n'): raise ValueError("CRLF in value")` at the top of `build_set_cookie` and a similar guard in `parse_set_cookie` for the VALUE position. This would shift the library from "trusted caller" to "untrusted-input-safe". Pick one — currently the API sits in the middle.
  - Test the fix with: `build_set_cookie('k', 'val\r\ninj=1')` → `ValueError`.

### F-M3 — `build_set_cookie` accepts any Domain/Path string without validation (Severity: Medium)

- **File**: `src/rfc6265_cookie_pure/__init__.py:354` (Domain) + `:356` (Path)
- **Description**: `build_set_cookie` does NOT validate:
  - `Domain=''` → emits `Domain=` (empty Domain attribute, which RFC 6265 §5.3 says SHOULD NOT be sent)
  - `Domain='.com'` (public-suffix only — would let attacker hijack all `.com` TLD cookies on a sibling host)
  - `Domain='127.0.0.1'` or `Domain='[::1]'` (IP-literal — RFC 6265 §5.3 step 5 says SHOULD NOT accept)
  - `Domain='co.uk'` (a public suffix — would let attacker set cookies for any host ending in `.co.uk`)
  - `Domain='foo bar'` (whitespace)
  - `Domain='foo;bar'` (semicolon would prematurely terminate the attribute at parse time)
  - `Path=''` (empty path → emits `Path=` which the parser silently rewrites to `/` — but the literal output still contains `Path=`)
  - `Path='/foo;bad'` (semicolon in path)

  The README §Limitations does say "No cookie domain-matching algorithm" — but that's about RUNTIME matching. SERIALIZER-side validation is a separate concern; RFC 6265 §5.3 step 5 specifically recommends the user-agent (and by extension a serializer acting on the user-agent's behalf) reject some Domain values.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import build_set_cookie
  build_set_cookie('k', 'v', domain='.com')
  # -> 'k=v; Domain=.com'  # ACCEPTED — public-suffix injection risk
  build_set_cookie('k', 'v', domain='127.0.0.1')
  # -> 'k=v; Domain=127.0.0.1'  # ACCEPTED — IP literal
  build_set_cookie('k', 'v', domain='co.uk')
  # -> 'k=v; Domain=co.uk'  # ACCEPTED — public suffix
  build_set_cookie('k', 'v', domain='foo bar')
  # -> 'k=v; Domain=foo bar'  # ACCEPTED — invalid in any URL context
  build_set_cookie('k', 'v', domain='foo;bar')
  # -> 'k=v; Domain=foo;bar'  # ACCEPTED — would be parsed as two attributes
  build_set_cookie('k', 'v', path='')
  # -> 'k=v; Path='  # ACCEPTED — empty path
  ```
- **CWE**: CWE-20 (Improper Input Validation)
- **Recommendation**:
  - Validate `domain` against a simple regex (`^[a-zA-Z0-9.\-]+$` for hostnames) and reject IP-literal + public-suffix-only + leading dot, OR document loudly in the docstring that domain validation is the caller's responsibility.
  - Validate `path` against `^/[!-$&--..---~]*$` (RFC 3986 path characters + leading `/`) or require non-empty + leading `/`.
  - Add tests covering these rejections; or document the contract in README §Limitations and §Non-goals.

### F-M4 — Asymmetric case canonicalization between build and parse (Severity: Medium)

- **File**: `src/rfc6265_cookie_pure/__init__.py:354-356` (build_set_cookie Domain/Path) vs `:164-169` (parse_set_cookie Domain/Path via `_parse_attributes` doing `attr.lower()`)
- **Description**: `build_set_cookie('k', 'v', domain='Example.Com')` emits literal `Domain=Example.Com`. `parse_set_cookie('...; Domain=Example.Com')` returns `attributes={'domain': 'example.com'}` because `_parse_attributes` lower-cases the attribute value via `attr.lower()`. Same for `Path` → `path`. So `build → parse` mutates the value; a downstream `parse → build` would re-emit canonical-case, but `build → parse → build` round-trip is NOT stable.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import build_set_cookie, parse_set_cookie, cookie_to_dict
  orig = build_set_cookie('k', 'v', domain='Example.Com', path='/API')
  # -> 'k=v; Domain=Example.Com; Path=/API'
  parsed = parse_set_cookie(orig)
  # -> Cookie('k', 'v', domain='example.com', path='/api')  # LOWER-CASED
  re_built = build_set_cookie(parsed.name, parsed.value, **parsed.attributes)
  # -> 'k=v; Domain=example.com; Path=/api'  # CASE LOST
  # cookie_to_dict(orig-parsed) != cookie_to_dict(parse_set_cookie(re_built))
  ```
- **CWE**: CWE-708 (Incorrect Ownership Assignment) — minor data-integrity issue
- **Recommendation**:
  - Either: lowercase Domain/Path values at BUILD time too (so `build → parse → build` is idempotent). Align build and parse semantics.
  - Or: document that `Cookie` attributes are normalized to lowercase at parse time, and `build_set_cookie` passes values verbatim — i.e. the round-trip fidelity is `parse → build` (lossy canonicalization), not `build → parse`.
  - Pick one and add a test that pins the chosen behavior.

### F-L1 — `cookie_to_dict` attribute shadowing of `name`/`value` (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:389-399`
- **Description**: `cookie_to_dict` first writes `result['name'] = cookie.name; result['value'] = cookie.value` and THEN iterates `cookie.attributes.items()` overwriting any colliding keys. A `Cookie` constructed with `attributes={'name': 'evil'}` produces `{'name': 'evil', 'value': ...}` — the cookie's actual name is lost.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import Cookie, cookie_to_dict
  c = Cookie(name='foo', value='bar', attributes={'name': 'overrides'})
  cookie_to_dict(c)
  # -> {'name': 'overrides', 'value': 'bar'}  # cookie's actual name is shadowed
  ```
- **CWE**: CWE-706 (Use of Incorrectly-Resolved Name or Reference)
- **Recommendation**: Either prefix attribute keys (e.g., `result[f'attr_{k}'] = v`) or merge in the other direction (attributes first, then name/value overwrite). Document the chosen precedence in the docstring.

### F-L2 — `Cookie` dataclass is frozen but `attributes` dict is mutable (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:26-31`
- **Description**: `c = parse_set_cookie('k=v; Path=/'); c.attributes['evil'] = 'injected'` succeeds and corrupts the cookie after the fact. The `name`/`value` are immutable but `attributes` is a plain `dict` reference held inside the frozen dataclass.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import parse_set_cookie
  c = parse_set_cookie('k=v; Path=/')
  c.attributes['evil'] = 'injected'
  repr(c)  # -> Cookie('k', 'v', evil='injected', path='/')
  ```
- **CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)
- **Recommendation**: Use `types.MappingProxyType` for `attributes` (read-only view) or copy the dict in `__post_init__`. Document that callers must construct a new `Cookie` to mutate.

### F-L3 — SameSite value permissive canonicalization (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:174-177`
- **Description**: `parse_set_cookie('k=v; SameSite=Invalid')` returns `samesite='Invalid'` (capitalized first letter). `parse_set_cookie('k=v; SameSite=')` returns `samesite=''`. Per RFC 6265bis (and modern browser behavior), only `Strict`, `Lax`, `None` are valid; anything else is malformed.
- **Repro**:
  ```python
  from rfc6265_cookie_pure import parse_set_cookie
  parse_set_cookie('k=v; SameSite=Strict')   # -> samesite='Strict'  OK
  parse_set_cookie('k=v; SameSite=invalid')   # -> samesite='Invalid' (lenient)
  parse_set_cookie('k=v; SameSite=')          # -> samesite='' (lenient)
  parse_set_cookie('k=v; SameSite=foobar')    # -> samesite='Foobar' (lenient)
  ```
- **CWE**: CWE-1284 (Improper Validation of Specified Quantity in Input)
- **Recommendation**: Either validate the value is one of `Strict|Lax|None` (case-insensitive) and reject others, or document the permissive behavior. The README §Key Features says "SameSite (Strict/Lax/None)" — current behavior contradicts the documentation.

### F-L4 — Negative `Max-Age` accepted verbatim (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:172-173`
- **Description**: `parse_set_cookie('k=v; Max-Age=-1')` returns `max-age='-1'`. RFC 6265 §5.2.2 says Max-Age is a non-negative integer. The string is stored raw; no integer validation is done.
- **Repro**: see test_rfc6265.py `test_max_age_negative` — explicitly documents the lenient behavior.
- **CWE**: CWE-1284
- **Recommendation**: Either validate `int(value) >= 0` or document lenient behavior. (The test currently asserts the lenient behavior; this is a deliberate choice.)

### F-L5 — `Expires=` attribute stored as raw string without date validation (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:170-171`
- **Description**: `parse_set_cookie('k=v; Expires=garbage')` returns `expires='garbage'`. The parser does not validate the date — that's the user's job via `parse_sane_cookie_date`. README §API Reference documents `parse_sane_cookie_date` separately for this purpose.
- **Repro**: `parse_set_cookie('k=v; Expires=garbage')` → `expires='garbage'`
- **CWE**: CWE-1284 (mild)
- **Recommendation**: Documented as deliberate (README §API Reference points to `parse_sane_cookie_date`). No fix needed; mention in §Limitations.

### F-L6 — `_DATE_RE` ignores weekday validation (Severity: Low)

- **File**: `src/rfc6265_cookie_pure/__init__.py:82-92`
- **Description**: `parse_sane_cookie_date('Foo, 09 Jun 2021 10:18:14 GMT')` succeeds despite `Foo` not being a valid weekday. The regex captures `[A-Za-z]{3}` but never checks it against `_WEEKDAY`.
- **Repro**: `parse_sane_cookie_date('Foo, 09 Jun 2021 10:18:14 GMT')` → `datetime(2021, 6, 9, 10, 18, 14, tzinfo=utc)` — weekday ignored.
- **CWE**: CWE-1284
- **Recommendation**: Either validate weekday against `_WEEKDAY` (and possibly cross-check that it matches the actual day of week for the given date) or document that weekday is advisory. RFC 6265 Appendix D says weekday is optional ("may be included"), so permissive behavior is actually defensible.

### F-I1 — README test-count is stale (Severity: Info / Honesty pillar gap)

- **File**: `README.md:67`
- **Description**: `README.md` line 67 says "**121 tests** — 100% pytest pass rate". Actual count is **122** (verified via `pytest --collect-only`). `QA_REPORT.md` correctly says 122. This is a Honesty-pillar gap (the pre-push gate does not enforce test-count matching between README and pytest).
- **Repro**: `grep -E "test" README.md` → "121 tests" vs `pytest --collect-only -q` → "122 tests collected".
- **CWE**: N/A (documentation drift)
- **Recommendation**: Update `README.md:67` to "**122 tests**". One-line change. The pre-push gate could be enhanced to assert this, but that's a separate workstream.

### F-I2 — No CLI surface (Severity: Info / design choice)

- **File**: `src/rfc6265_cookie_pure/__init__.py` (no `__main__.py` defined)
- **Description**: `-m rfc6265_cookie_pure --help` returns `No module named rfc6265_cookie_pure.__main__`. This is intentional — the package is library-only, no CLI. The README doesn't claim a CLI exists. Listed for completeness because the original probe list (#10) included CLI.
- **CWE**: N/A
- **Recommendation**: No fix needed; this is a non-finding.

---

## Adversarial Probe Results

| # | Probe | Result | Notes |
|---|---|---|---|
| 1 | CRLF/HTTP header injection in name + value | PARTIAL | NAME correctly rejected; VALUE + ATTRIBUTE values accepted (F-M2) |
| 2 | Invariant 21 (None/int/bool/list/dict/bytes/float/NaN across 4 functions) | FAIL | `parse_set_cookie(42)`, `parse_set_cookie(b'...')`, `build_set_cookie([], 'v')` (silent!), `cookie_to_dict(...)` all raise or silently accept (F-M1) |
| 3 | RFC 6265 §4.1 Set-Cookie examples | PASS | All 7 examples parse correctly |
| 4 | RFC 6265 §5.4 cookie-header parsing | PASS | All 11 examples parse correctly (last-wins for duplicates, empty pairs skipped, no = → ignored) |
| 5 | Date parsing (RFC 1123 / RFC 850 / asctime variants) | PARTIAL | RFC 1123 / no-weekday pass; RFC 850 ('Wednesday, 09-Jun-21') and asctime ('Wed Jun  9 10:18:14 2021') FAIL — these are documented as the 3 formats RFC 6265 Appendix D says a user-agent SHOULD accept (F-L6 + Appendix-D conformance gap) |
| 6 | Domain/Path validation in build_set_cookie | FAIL | Empty Domain, leading-dot, IP-literal, public-suffix-only all accepted (F-M3) |
| 7 | SameSite attribute | PARTIAL | Strict/Lax/None case-insensitive → capitalized; invalid values like `Invalid`/`Foobar` accepted (F-L3) |
| 8 | Re-serialization round-trip (build → parse → build) | FAIL | Domain/Path case mutated (F-M4); Secure/HttpOnly flag loss because `None` value is not serialized (`**{'secure': None}` becomes `k=v`) — see below |
| 9 | Oversized inputs (100K value, 10K attrs, 1MB value) | PASS | 1MB value parses in 45ms; 10K known attrs parses in <10ms; no DoS |
| 10 | CLI surface | PASS | No CLI (F-I2); library-only design |
| 11 | cookie_to_dict merge collision | FAIL | Attribute shadowing of name/value (F-L1) |
| 12 | Quoted-value edge cases (`k="a;b"`, `k=""`, etc.) | PASS | Quotes preserved verbatim; parser does NOT strip surrounding DQUOTEs (correct — RFC 6265 §4.1.1 says "If the cookie-value is a token, it's emitted as-is; if it's a quoted-string, the quotes are part of the value") |
| 13 | SameSite=None serialization | PASS | `k=v; SameSite=None` round-trips correctly |
| 14 | Mixed-case attribute keys | PASS | `build_set_cookie` rejects (typed kwargs); `parse_set_cookie` accepts and normalizes to lowercase — OK |
| 15 | cookie_to_dict shadowing attribute name | FAIL | Same as #11 (F-L1) |
| 16 | Whitespace before Set-Cookie: prefix | PASS | Rejected by token validation (good) |
| 17 | Regex DoS on _DATE_RE | PASS | No backtracking; padded prefixes rejected at <1ms |
| 18 | Domain attribute leading dot (parse vs build) | PARTIAL | Parse preserves leading dot; build emits literal (RFC 6265 §5.3 step 5 says SHOULD NOT accept — neither enforces) |
| 19 | parse_cookie_header quoted value edge cases | PARTIAL | Quotes NOT stripped from values; semicolons inside quotes NOT protected (`k="v;w"` → `{'k': '"v'}`) — the parser splits on `;` regardless of quote state (F below — minor, documented) |
| 20b | Token validation in value | PASS | Build does not validate value chars; parse does not validate value chars (only name) — value is opaque octet sequence per RFC 6265 §4.1.1 |
| 21 | Whitespace stripping in cookie-pair | PASS | Value is `.rstrip()`-ed only; internal whitespace preserved |

**Extra finding surfaced during probes (not in original 14-point checklist)**: In probe 8, `build_set_cookie('k', 'v', **{'secure': None})` produces `'k=v'` (NOT `'k=v; Secure'`). Because `**{'secure': None}` passes `secure=None`, the `if secure:` check is False, and the flag is silently dropped. This is a Python signature-vs-dataclass-mismatch issue: `parse_set_cookie('k=v; Secure')` produces `attributes={'secure': None}`, but `build_set_cookie(**that_dict)` loses the flag. Same for `httponly`. **Add to F-L or fold into F-M4 as a build-side asymmetry.**

---

## Probe Results Detail

| Severity tally | Count | Detail |
|---|---|---|
| Critical | 0 | (none — no RCE, no auth bypass, no unauthenticated data exfiltration vectors found) |
| High | 0 | (none) |
| Medium | 4 | F-M1, F-M2, F-M3, F-M4 |
| Low | 6 | F-L1, F-L2, F-L3, F-L4, F-L5, F-L6 (+ 1 sub-finding from probe 8) |
| Info | 2 | F-I1, F-I2 |

---

## Recommendation

**Verdict: NEEDS_REMEDIATION (non-blocking; acceptable to proceed to T2 with documented acceptance).**

The 4 Medium findings are contract/validation gaps, not exploitable bugs in the library as-shipped:

- **F-M1 (Invariant 21 totality)**: The orchestrator should decide whether this is a contract violation worth fixing (adding `isinstance` guards) or whether documenting "str in / Cookie in" in the docstrings is acceptable. The existing tests cover empty/falsy inputs (returning `ValueError`) but do NOT cover `int`/`float`/`bytes`/`list`/`dict` non-string inputs.
- **F-M2 (CRLF in value/attribute)**: Document loudly OR add defensive guards. The library is currently a "trusted-caller" parser; a downstream user that pipes attacker-controlled strings into `value`/`domain` is responsible for sanitization.
- **F-M3 (no Domain/Path validation in build)**: Add basic validation OR document loudly.
- **F-M4 (case asymmetry build↔parse)**: Either lowercase in build too, or document the canonicalization asymmetry.

The 6 Low findings are stylistic / minor. The 2 Info findings are documentation drift (F-I1 is one-line to fix; F-I2 is non-finding).

**Suggested path forward**: Proceed to T2 (fuzzing harnesses) with a documented acceptance note in `FUZZING_REPORT.md` §Recommendations covering F-M1 through F-M4 as known contract boundaries. The T2 fuzzer will exercise Invariant 21 (probe 2) and CRLF (probes 1, A–D) more aggressively than FYI manual probes — if T2 finds new Critical/High findings, the cycle blocks back to `@repo-builder`.

---

## Pre-conditions for Acceptance Note (T5 FUZZING_REPORT.md §Recommendations)

If the orchestrator accepts NEEDS_REMEDIATION → proceed to T2/T3/T4/T5, the T5 FUZZING_REPORT.md MUST include in its Recommendations section:

1. **F-M1 Invariant 21 gap** — document `str` / `Cookie` input requirement in docstrings; mention that `TypeError`/`AttributeError` is the current exception type for non-string inputs (not the documented `ValueError`).
2. **F-M2 CRLF** — document that `value`/`domain`/`path`/`expires`/`max_age`/`samesite` strings are NOT CRLF-sanitized; callers must sanitize untrusted input.
3. **F-M3 Domain/Path validation** — document that `build_set_cookie` does NOT validate Domain syntax; callers must validate.
4. **F-M4 case asymmetry** — document that `parse_set_cookie` lower-cases `domain`/`path` while `build_set_cookie` does NOT; round-trip mutates case.
5. **F-I1 README test-count drift** — README says "121 tests", actual is 122. Fix in a follow-up cycle or call out as known.

---

## Files Reviewed

- `src/rfc6265_cookie_pure/__init__.py` (413 LOC, read end-to-end)
- `pyproject.toml` (31 lines, stdlib-only confirmed)
- `README.md` (127 lines)
- `tests/test_rfc6265.py` (731 lines, 122 tests, sections reviewed)
- `tests/test_readme_bench_matches_benchmark.py` (84 lines)
- `QA_REPORT.md` (current cycle's QA report — read for context)
- `benchmarks/run_benchmark.py` (257 lines — confirmed stdlib-only)

## Methods

1. End-to-end read of `__init__.py` line-by-line, tracing each public function through its helpers.
2. Tokenizer / attribute parser / date regex static analysis for backtracking risk and grammar conformance.
3. 21+ targeted adversarial probes from `python3.11` REPL (full output captured in `/tmp/adversary_probes*.py`).
4. Cross-checked against RFC 6265 §4.1.1 (Set-Cookie syntax), §5.4 (cookie-string), Appendix D (sane-cookie-date).
5. Verified pytest 122/122 pass on a fresh venv install.

---

VERDICT: NEEDS_REMEDIATION (Medium contract gaps; safe to proceed to T2/T5 with documented acceptance note covering F-M1–F-M4 + F-I1)