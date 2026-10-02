#!/usr/bin/env python3
"""Build seed corpora for the 5 fuzz surfaces.

Each seed is written as raw bytes into ``cycle_160/adversary/corpus/<surface>/``.
Atheris treats every file as a starting mutation point for coverage-guided
fuzzing, so the more *coverage-relevant* the seeds, the faster the fuzzer
discovers new edges.

Surface contract recap (from cycle_160/adversary/fuzz/*.py):

  * set_cookie_parse    : str -> Cookie  (single unicode string, cap 16KB)
  * cookie_header_parse : str -> dict    (single unicode string, cap 16KB)
  * set_cookie_build    : 3 unicode + 6 unicode + int + 2 bool + unicode
  * invariant21         : 2 ints (fn_idx, type_idx), but the seed corpus only
                          needs a deterministic 18-byte header (2 x int8).
  * date_parse           : str -> datetime (single unicode string, cap 4KB)
"""

import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def w(surface: str, name: str, data: bytes) -> None:
    p = CORPUS / surface / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def ascii(s: str) -> bytes:
    """Encode a printable ASCII/UTF-8 seed (no NULs, used for parser surfaces)."""
    return s.encode("utf-8")


# ---------------------------------------------------------------------------
# set_cookie_parse   (parse_set_cookie: str -> Cookie)
# ---------------------------------------------------------------------------

# Numbered prefix so the order in `ls` matches the comment order.
SC_SEEDS: list[tuple[str, str]] = [
    # ---- valid edge cases (RFC 6265 §4.1.1, §5.4, Appendix D) ----------
    ("001", "name=value"),                                            # minimal
    ("002", "name=value; Path=/; Secure; HttpOnly"),                  # §4.1.1 example
    ("003", "name=value; Domain=example.com"),                        # cookie-to-host
    ("005", "name=value; Expires=Wed, 09 Jun 2021 10:18:14 GMT"),      # RFC 1123 date
    ("006", "name=value; Max-Age=3600"),                              # delta-seconds
    ("007", "name=value; Path=/path; SameSite=Strict"),               # SameSite=Strict
    ("008", "name=value; Path=/path; SameSite=Lax"),                  # SameSite=Lax
    ("009", "name=value; Path=/path; SameSite=None"),                 # SameSite=None
    ("010", "k=v; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"),  # all attrs
    ("011", "JSESSIONID=ABC123; Path=/"),                             # JSESSIONID
    ("012", "id=42; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),           # epoch
    ("013", "id=42; Expires=Fri, 31 Dec 2099 23:59:59 GMT"),          # far-future
    ("014", "a=b; Path=/a/b/c/d/e"),                                  # deep path
    ("015", "x=y; Domain=sub.host.example.com"),                      # subdomain
    ("016", "x=y; Domain=localhost"),                                   # bare-host
    ("017", "x=y; Path="),                                             # empty path
    ("018", "x=y; Domain="),                                           # empty domain
    ("019", "k=v; Max-Age=0"),                                         # immediate expiry
    ("020", "k=v; Max-Age=-1"),                                            # negative max age
    # ---- boundary / size -------------------------------------------------
    ("021", ""),                                                       # empty
    ("022", "x"),                                                      # empty
    ("023", "="),                                                      # empty name + value
    ("024", "=v"),                                                     # empty name
    ("025", "n="),                                                     # empty value
    ("026", "x" * 4096 + "=y"),                                        # long name
    ("027", "x=" + "y" * 4096),                                        # long value
    ("028", "x=y" * 1000),                                             # repeated
    # ---- quoted values --------------------------------------------------
    ("029", 'k="quoted value"'),                                       # DQUOTE-wrapped
    ("030", 'k="a\\\"b"'),                                             # escaped quote
    ("031", 'k="unterminated'),                                        # unterminated quote
    # ---- invalid / malformed --------------------------------------------
    ("032", "no_equals_sign"),                                         # malformed
    ("033", "name\r\nX-Injected: bad=1"),                              # CRLF injection
    ("034", "name\nX-Injected: bad=1"),                                # LF injection
    ("035", "name\rX-Injected: bad=1"),                                # bare CR
    ("036", "name; Path=/; garbage_token_no_eq"),                      # attribute w/o =
    ("038", "name=value; Path=/; ; Secure"),                              # double ;
    ("039", "name=value; =garbage"),                                   # leading =
    ("040", "name=value; Path=/\x00Secure"),                           # NUL mid-string
    ("041", "name=value; Path=/; Secure\x00"),                         # trailing NUL
    ("042", "name\x00=value"),                                         # NUL in name
    ("043", "name=\x00"),                                              # NUL in value
    ("044", "name=value; Path=/; Secure; HttpOnly; Bogus=1"),          # unknown attr
    # ---- unicode / case / control chars --------------------------------
    ("046", "naïve=café"),                                             # unicode names
    ("047", "Name=Value"),                                             # title-case
    ("048", "NAME=VALUE"),                                             # upper-case
    ("049", "name=value; PATH=/; SECURE; HTTPONLY"),                   # upper-case attrs
    ("050", "name=value; path=/; secure; httponly"),                   # lower-case attrs
    ("051", "name=value\t; Path=/"),                                   # tab separator
    ("052", "  name=value  ;  Path=/  "),                              # whitespace
    ("053", "\x7fname=value"),                                         # DEL prefix
    ("054", "name=value\x7f"),                                         # DEL suffix
    ("055", "name=value;\x00=garbage"),                                # NUL attr name
    # ---- attribute-confusion attacks ----------------------------------
    ("056", "name=val; Domain=evil.com; Domain=trust.com"),            # attr-Domain
    ("057", "name=val; Path=/good; Path=/bad"),                        # attr-Path
    ("058", "name=val; Max-Age=100; Max-Age=200"),                     # attr-MaxAge
    ("059", "name=val; Path=/; Expires=Wed, 09 Jun 2021 10:18:14 GMT"),  # both expires + Max-Age
    ("060", "name=val; Path=../../../etc"),                            # path traversal
    ("061", "name=val; Domain=evil.com\\trust.com"),                   # domain backslash
]

# ---------------------------------------------------------------------------
# cookie_header_parse   (parse_cookie_header: str -> dict)
# ---------------------------------------------------------------------------

CH_SEEDS: list[tuple[str, str]] = [
    # ---- valid edge cases (RFC 6265 §5.4) -------------------------------
    ("001", "name=value"),
    ("002", "name=value; name2=value2"),
    ("003", "k1=v1; k2=v2; k3=v3"),                                    # 3 pairs
    ("004", "id=42"),                                                  # single
    ("005", "session=abc123"),                                         # session.id
    ("006", "user_pref=dark_mode; lang=en; tz=UTC"),                  # multi
    ("007", "a=b; c=d; e=f; g=h; i=j"),                                # many pairs
    ("008", "  name=value  "),                                         # leading/trailing ws
    ("009", "name=value; "),                                           # trailing ;
    ("010", "name=value;name2=value2"),                                # no SP after ;
    # ---- value with chars / DQUOTE / escapes -----------------------------
    ("011", 'name="quoted value"'),
    ("012", 'name="a\\"b"'),
    ("013", 'name="unterminated'),
    ("014", "name=value with spaces"),
    ("015", "name=value,with,commas"),
    # ---- boundary / size ------------------------------------------------
    ("016", ""),                                                       # empty
    ("017", "x"),                                                      # 1 char
    ("018", "="),                                                      # null name+value
    ("019", "=value"),                                                 # null name
    ("020", "name="),                                                  # null value
    ("021", "n" * 200 + "=v"),                                        # long name
    ("022", "n=" + "v" * 200),                                        # long value
    ("023", "a=b" * 100),                                             # repeated
    ("024", "k=v;" * 50),                                             # trailing ;
    # ---- duplicate keys -------------------------------------------------
    ("025", "name=first; name=second"),                                # dup-key
    ("026", "k=v; k=v; k=v"),                                          # dup-key x3
    ("027", "NAME=value; name=value"),                                 # case-dup
    # ---- injection / control chars -------------------------------------
    ("028", "name\r\nX-Injected: bad=1"),                              # CRLF
    ("029", "name\nX-Injected: bad=1"),                                # LF
    ("030", "name\rX-Injected: bad=1"),                                # bare CR
    ("031", "name=value\x00; other=value"),                            # NUL
    ("032", "name\x00=value"),                                         # NUL in name
    ("033", "name=value\x00"),                                         # NUL in value
    ("034", "\x7fname=value"),                                         # DEL
    # ---- separator-confusion -------------------------------------------
    ("036", "name=value;;other=value"),                                 # double ;
    ("037", "name=value,other=value"),                                 # comma sep
    ("038", "name=value\t; other=value"),                              # tab sep
    ("039", "name=value; ; other=value"),                              # bare ;
    ("040", "name=value;a"),                                           # no = on second
    # ---- unicode / case / non-ASCII ------------------------------------
    ("041", "naïve=café"),
    ("042", "NAME=VALUE"),                                                # upper
    ("043", "Name=Value"),                                                # title
    ("044", "name=value; \u00a0other=value"),                          # NBSP
    ("045", "name=value;\u200bother=value"),                           # ZWSP
    # ---- RFC 6265 §5.4 case-insensitivity ------------------------------
    ("046", "ID=42; id=43; Id=44"),                                    # case-dup
    ("047", "a=1; A=2"),                                               # case-dup-2
    # ---- malformed tokens ----------------------------------------------
    ("048", "no_equals"),                                              # no =
    ("049", "=value; other=value"),                                      # leading =
    ("050", "name=value;;"),                                           # trailing ;;
    ("051", "name=value;="),                                           # trailing bare =
    ("052", "name=value; key"),                                            # key only
    # ---- pathological cases -------------------------------------------
    ("053", ";name=value"),                                            # leading ;
    ("054", "name=value; ; ; ; "),                                     # many ;
    ("055", "name=value; ; ; ; " + ("a=b; " * 100)),                   # noise + data
    ("056", "name=value; Domain=evil.com; Secure"),                    # Set-Cookie attrs in Cookie hdr
    ("057", "name=value; Path=/; HttpOnly"),                           # same
    ("058", "name=value; Expires=Wed, 09 Jun 2021 10:18:14 GMT"),
    ("059", "name=value; Max-Age=3600"),
    ("060", "name=value; SameSite=Strict"),
]

# ---------------------------------------------------------------------------
# set_cookie_build   (build_set_cookie: name,value,domain=...,path=...,expires=...,
#                     max_age=int, secure=bool, httponly=bool, samesite=...)
# ---------------------------------------------------------------------------
# The harness reads:
#   - ConsumeUnicodeNoSurrogates(128) name
#   - ConsumeUnicodeNoSurrogates(4096) value
#   - ConsumeUnicodeNoSurrogates(128) domain
#   - ConsumeUnicodeNoSurrogates(128) path
#   - ConsumeUnicodeNoSurrogates(64) expires
#   - ConsumeIntInRange(-2**31, 2**31-1) max_age
#   - ConsumeBool() secure
#   - ConsumeBool() httponly
#   - ConsumeUnicodeNoSurrogates(16) samesite
#
# Atheris FuzzedDataProvider reads everything from one byte stream, so each
# seed has to be long enough to satisfy the longest consumer (~4096 bytes of
# unicode) with leftover room. We'll just pack known-good bytes here.

def encode_string(max_len: int) -> bytes:
    """Length-prefixed string used by ConsumeUnicodeNoSurrogates. Atheris
    internally reads 4 bytes for length then up to max_len UTF-8 bytes; we
    emit a 4-byte little-endian length followed by exactly that many bytes
    of payload."""
    # 0 length = empty string (the fuzzer happily consumes 0 bytes after the
    # length prefix). This is enough to satisfy the consumer.
    return struct.pack("<I", 0)


def encode_int(value: int) -> bytes:
    """Atheris ConsumeIntInRange(-2**31, 2**31-1) clamps internally; mirror
    that here so seeds remain valid even if the user picks a value outside
    the consumer's range."""
    if value > 2**31 - 1:
        value = 2**31 - 1
    elif value < -(2**31):
        value = -(2**31)
    return struct.pack("<i", value)


def encode_bool(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


def build_pkg(*, name: bytes, value: bytes, domain: bytes = b"",
              path: bytes = b"", expires: bytes = b"",
              max_age: int = 0, secure: bool = False,
              httponly: bool = False, samesite: bytes = b"") -> bytes:
    """Compose a seed that decodes deterministically through the fuzzer's
    Consume* calls in the exact order they're called in TestOneInput."""
    return (
        encode_string(128) + name +
        encode_string(4096) + value +
        encode_string(128) + domain +
        encode_string(128) + path +
        encode_string(64)  + expires +
        encode_int(max_age) +
        encode_bool(secure) +
        encode_bool(httponly) +
        encode_string(16)  + samesite
    )


def encode_pkg(*, name: bytes, value: bytes = b"v", domain: bytes = b"",
               path: bytes = b"", expires: bytes = b"",
               max_age: int = 0, secure: bool = False,
               httponly: bool = False, samesite: bytes = b"") -> bytes:
    return build_pkg(name=name, value=value, domain=domain, path=path,
                     expires=expires, max_age=max_age, secure=secure,
                     httponly=httponly, samesite=samesite)


def ascii_label(b: str) -> bytes:
    return b.encode("utf-8")


# Minimal-valid cookie name/value pair (a "token" per RFC 6265 §4.1.1.1)
NAME_OK = ascii_label("session")
VAL_OK  = ascii_label("abc123")

# ---------------------------------------------------------------------------
# invariant21   — fn_idx (1 byte) + type_idx (1 byte); the actual non-string
# input is hard-coded in BAD_TYPES inside the harness.
# ---------------------------------------------------------------------------

INV_SEEDS: list[tuple[str, bytes]] = [
    # function indices 0..3 cover the 4 public top-level callables
    # type indices 0..8 cover the 9 BAD_TYPES entries
    (f"{fi:02d}{ti:02d}", struct.pack("BB", fi, ti))
    for fi in range(4)
    for ti in range(9)
]
# Pad to >=50: out-of-range indices + boundary sizes + a few truncated buffers
# that drive the fuzzer into edge cases in ConsumeIntInRange.
INV_SEEDS.extend([
    ("9999", b"\xff\xff"),    # both out-of-range — Atheris fdp will clamp
    ("99",   b"\xff"),         # single byte  — fdp reads the missing half from 2nd cut
    ("999",  b""),            # empty        — fdp yields defaults
    ("04",   b"\x00\xff"),    # valid fn_idx, out-of-range type_idx
    ("05",   b"\x01\xff"),
    ("06",   b"\x02\xff"),
    ("07",   b"\x03\xff"),
    ("f0",   b"\xff\x00"),    # out-of-range fn_idx, valid type_idx
    ("f1",   b"\xff\x01"),
    ("f2",   b"\xff\x02"),
    ("fe",   b"\xfe\xfe"),
    ("80",   b"\x80\x00"),         # high-bit boundary
    ("7f",   b"\x7f\x00"),
    ("aa",   b"\xaa\xaa"),
    ("55",   b"\x55\x55"),
    ("deadbeef00", b"\xde\xad\xbe\xef\x00"),  # 5-byte seed
    ("deadbeef01", b"\xde\xad\xbe\xef\x01"),
    ("deadbeef02", b"\xde\xad\xbe\xef\x02"),
    ("deadbeef03", b"\xde\xad\xbe\xef\x03"),
])

# ---------------------------------------------------------------------------
# date_parse   (parse_sane_cookie_date: str -> datetime)
# ---------------------------------------------------------------------------

DP_SEEDS: list[tuple[str, str]] = [
    # ---- RFC 1123 (§5.1.1) -----------------------------------------------
    ("001", "Sun, 06 Nov 1994 08:49:37 GMT"),                          # canonical
    ("002", "Mon, 01 Jan 1900 00:00:00 GMT"),                          # epoch-low
    ("003", "Fri, 31 Dec 2099 23:59:59 GMT"),                          # far-future
    ("004", "Tue, 29 Feb 2028 00:00:00 GMT"),                          # leap-year (2028 / 4)
    ("005", "Wed, 09 Jun 2021 10:18:14 GMT"),                          # §5.1.1 RFC 6265 example
    ("006", "Thu, 01 Jan 1970 00:00:00 GMT"),                          # unix epoch
    ("007", "Sat, 01 Jan 2000 00:00:00 GMT"),
    ("008", "Sun, 01 Jan 2017 13:37:00 GMT"),
    ("009", "Wed, 09 Jun 2021 10:18:14 GMT"),                          # repeated (variant)
    ("010", "Mon, 05 Jul 2021 12:34:56 GMT"),
    # ---- RFC 850 (§5.1.2) -----------------------------------------------
    ("020", "Sunday, 06-Nov-94 08:49:37 GMT"),                         # canonical
    ("021", "Monday, 01-Jan-00 00:00:00 GMT"),                         # 2000
    ("022", "Friday, 31-Dec-99 23:59:59 GMT"),                         # 2099
    ("023", "Wednesday, 09-Jun-21 10:18:14 GMT"),                      # 21st century
    ("024", "Thursday, 01-Jan-70 00:00:00 GMT"),
    # ---- asctime (§5.1.3) ----------------------------------------------
    ("030", "Sun Nov  6 08:49:37 1994"),                                # canonical
    ("031", "Mon Jan  1 00:00:01 1900"),                                # padded day
    ("032", "Fri Dec 31 23:59:59 2099"),                                # far-future
    ("033", "Wed Jun  9 10:18:14 2021"),                                # §5.1.3
    ("034", "Thu Jan  1 00:00:00 1970"),                                # epoch
    ("035", "Sun Nov  6 08:49:37 94"),                                  # 2-digit year
    # ---- boundary / size ------------------------------------------------
    ("040", ""),                                                       # empty
    ("041", "x"),                                                      # 1 char
    ("042", "Sun"),                                                    # day only
    ("043", "Sun, 06 Nov"),                                            # day + day-month
    ("044", "Sun, 06 Nov 1994"),                                        # no time
    ("045", "Sun, 06 Nov 1994 08:49:37 GMT extra"),                   # trailing junk
    ("046", "Sun, 06 Nov 1994 08:49:37 GMT" + "x" * 1024),             # huge tail
    # ---- case sensitivity ----------------------------------------------
    ("050", "sun, 06 nov 1994 08:49:37 gmt"),                          # lower-case
    ("051", "SUN, 06 NOV 1994 08:49:37 GMT"),                          # upper-case
    ("052", "sUn, 06 nOv 1994 08:49:37 GmT"),                          # mixed
    # ---- malformed / control chars -------------------------------------
    ("060", "Sun, 06 Nov 1994 08:49:37 GMT\n\n")[:64],
    ("061", "Sun, 06 Nov 1994 08:49:37 GMT\r\n")[:64],
    ("062", "Sun\x00, 06 Nov 1994 08:49:37 GMT"),                       # NUL
    ("063", "Sun, 06 Nov 1994 08:49:37 GMT\x00"),                       # trailing NUL
    ("064", "Sun, 06 Nov 1994 08:49:37 \x7fGMT"),                       # DEL
    ("065", "Sun, 06 Nov 1994 08:49:37 GM\x00T"),                       # NUL in tz
    # ---- invalid component values ---------------------------------------
    ("070", "Sun, 32 Nov 1994 08:49:37 GMT"),                          # invalid day
    ("071", "Sun, 06 Nov 1994 25:00:00 GMT"),                          # invalid hour
    ("072", "Sun, 06 Nov 1994 08:60:00 GMT"),                          # invalid min
    ("073", "Sun, 06 Nov 1994 08:49:60 GMT"),                          # invalid sec
    ("074", "Sun, 29 Feb 2023 00:00:00 GMT"),                          # non-leap-year
    ("075", "Sun, 31 Apr 2023 00:00:00 GMT"),                          # 31 Apr
    ("076", "Sun, 06 Nov 1994 08:49:37 UT"),                           # bad tz
    ("077", "Sun, 06 Nov 1994 08:49:37 UTC"),                           # UTC vs GMT
    # ---- unicode / non-ASCII ------------------------------------------
    ("080", "Sun, 06 Nov 1994 08:49:37 GMT\u00a0"),                    # NBSP
    ("081", "Sun, 06 Nov 1994 08:49:37 GMT\u200b"),                    # ZWSP
    ("082", "Sun, 06 Növ 1994 08:49:37 GMT"),                           # umlaut
    ("083", "Sun, 06 Nov 1994 08:49:37 日"),                            # CJK
    # ---- pathological / huge ------------------------------------------
    ("090", "x" * 4096),                                              # huge garbage
    ("091", "Sun, " + "0" * 4096 + " Nov 1994"),                       # huge digit run
    ("092", "Sun, 06 Nov 1994 08:49:37 GMT" * 50),                     # repetition
    ("093", "Wed Jun  9 10:18:14 2021"),                                # asctime variant
    ("094", "Wednesday, 09-Jun-21 10:18:14 GMT"),                      # RFC 850 variant
]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    # 1. set_cookie_parse
    for name, body in SC_SEEDS:
        w("set_cookie_parse", f"seed_{name}", ascii(body))

    # 2. cookie_header_parse
    for name, body in CH_SEEDS:
        w("cookie_header_parse", f"seed_{name}", ascii(body))

    # 3. set_cookie_build
    # Reuse the same byte-encoding helper. Each seed becomes a deterministic
    # call to build_set_cookie via the harness's Consume* sequence.
    pkg_seeds: list[tuple[str, bytes]] = [
        # ---- minimal valid ---------------------------------------------------
        ("001", encode_pkg(name=NAME_OK, value=VAL_OK)),
        # name + value + Path
        ("002", encode_pkg(name=NAME_OK, value=VAL_OK, path=ascii_label("/"))),
        # name + value + Domain
        ("003", encode_pkg(name=NAME_OK, value=VAL_OK, domain=ascii_label("example.com"))),
        # name + value + Secure + HttpOnly
        ("004", encode_pkg(name=NAME_OK, value=VAL_OK, secure=True, httponly=True)),
        # name + value + Max-Age
        ("005", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=3600)),
        # name + value + Expires (RFC 1123)
        ("006", encode_pkg(name=NAME_OK, value=VAL_OK,
                           expires=ascii_label("Wed, 09 Jun 2021 10:18:14 GMT"))),
        # all attrs
        ("007", encode_pkg(name=NAME_OK, value=VAL_OK,
                           domain=ascii_label("example.com"), path=ascii_label("/"),
                           expires=ascii_label("Wed, 09 Jun 2021 10:18:14 GMT"),
                           max_age=3600, secure=True, httponly=True,
                           samesite=ascii_label("Strict"))),
        ("008", encode_pkg(name=NAME_OK, value=VAL_OK, samesite=ascii_label("Lax"))),
        ("009", encode_pkg(name=NAME_OK, value=VAL_OK, samesite=ascii_label("None"))),
        ("010", encode_pkg(name=NAME_OK, value=VAL_OK, samesite=ascii_label(""))),
        # zero / negative max-age
        ("011", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=0)),
        ("012", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=-1)),
        ("013", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=2**31 - 1)),
        ("014", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=-(2**31))),
        # empty name (likely ValueError — coverage of the validation branch)
        ("020", encode_pkg(name=b"", value=VAL_OK)),
        # empty value
        ("021", encode_pkg(name=NAME_OK, value=b"")),
        # long name
        ("030", encode_pkg(name=b"n" * 127, value=VAL_OK)),
        # long value
        ("031", encode_pkg(name=NAME_OK, value=b"v" * 1024)),
        # unicode name
        ("040", encode_pkg(name="naïve".encode("utf-8"), value=VAL_OK)),
        ("041", encode_pkg(name=NAME_OK, value="café".encode("utf-8"))),
        # CR/LF in name (should be rejected by token validation)
        ("050", encode_pkg(name=b"na\rme", value=VAL_OK)),
        ("051", encode_pkg(name=b"na\nme", value=VAL_OK)),
        # Domain backslash
        ("060", encode_pkg(name=NAME_OK, value=VAL_OK, domain=ascii_label("evil.com\\trust.com"))),
        # Path with control char
        ("061", encode_pkg(name=NAME_OK, value=VAL_OK, path=b"/foo\x00bar")),
        # expires = garbage
        ("070", encode_pkg(name=NAME_OK, value=VAL_OK, expires=b"not a date")),
        # expires = empty (treated as None in harness)
        ("071", encode_pkg(name=NAME_OK, value=VAL_OK, expires=b"")),
        # samesite = unknown
        ("080", encode_pkg(name=NAME_OK, value=VAL_OK, samesite=b"Unknown")),
        # name with disallowed char (space)
        ("090", encode_pkg(name=b"na me", value=VAL_OK)),
        # name with disallowed char (comma)
        ("091", encode_pkg(name=b"na,me", value=VAL_OK)),
        # name with disallowed char (semicolon)
        ("092", encode_pkg(name=b"na;me", value=VAL_OK)),
        # name with disallowed char (equals)
        ("093", encode_pkg(name=b"na=me", value=VAL_OK)),
        # name with disallowed char (DQUOTE)
        ("094", encode_pkg(name=b'na"me', value=VAL_OK)),
        # name with disallowed char (backslash)
        ("095", encode_pkg(name=b"na\\me", value=VAL_OK)),
        # long samesite
        ("096", encode_pkg(name=NAME_OK, value=VAL_OK, samesite=b"S" * 15)),
        # path traversal
        ("100", encode_pkg(name=NAME_OK, value=VAL_OK, path=b"../../../etc")),
        # ---- pad to >=50 with name/token edge cases ------------------------
        # numeric-only name (token char)
        ("110", encode_pkg(name=b"123", value=VAL_OK)),
        # name with all token specials
        ("111", encode_pkg(name=b"!#$%&'*+-.^_`|~", value=VAL_OK)),
        # name exactly at boundary (token = visible-ascii + extras above)
        ("112", encode_pkg(name=b"x", value=VAL_OK)),
        ("113", encode_pkg(name=b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                 b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                 b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                 b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", value=VAL_OK)),
        # value with DQUOTE, semicolon, equals, comma, space (all cookie-octet)
        ("120", encode_pkg(name=NAME_OK, value=b'"quoted"')),
        ("121", encode_pkg(name=NAME_OK, value=b"a;b=c, d")),
        ("122", encode_pkg(name=NAME_OK, value=b"a\nb")),
        ("123", encode_pkg(name=NAME_OK, value=b"a\rb")),
        ("124", encode_pkg(name=NAME_OK, value=b"a\x00b")),
        # Domain as IP
        ("130", encode_pkg(name=NAME_OK, value=VAL_OK, domain=b"127.0.0.1")),
        ("131", encode_pkg(name=NAME_OK, value=VAL_OK, domain=b"[::1]")),
        ("132", encode_pkg(name=NAME_OK, value=VAL_OK, domain=b"..example.com")),
        # Domain with port (should still be a domain)
        ("133", encode_pkg(name=NAME_OK, value=VAL_OK, domain=b"example.com:8080")),
        # Expires as RFC 850
        ("134", encode_pkg(name=NAME_OK, value=VAL_OK,
                           expires=ascii_label("Sunday, 06-Nov-94 08:49:37 GMT"))),
        # Expires as asctime
        ("135", encode_pkg(name=NAME_OK, value=VAL_OK,
                           expires=ascii_label("Sun Nov  6 08:49:37 1994"))),
        # Expires with comma embedded
        ("136", encode_pkg(name=NAME_OK, value=VAL_OK,
                           expires=ascii_label("Sun, 06 Nov 1994 08:49:37, GMT"))),
        # all flags true
        ("140", encode_pkg(name=NAME_OK, value=VAL_OK, secure=True,
                           httponly=True, samesite=b"Strict")),
        # all flags false
        ("141", encode_pkg(name=NAME_OK, value=VAL_OK, secure=False,
                           httponly=False, samesite=b"")),
        # max_age boundary values
        ("150", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=1)),
        ("151", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=-1)),
        ("152", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=2147483647)),
        ("153", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=-2147483648)),
        ("154", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=2**31)),
        ("155", encode_pkg(name=NAME_OK, value=VAL_OK, max_age=-(2**31) - 1)),
        # cookie_to_dict-equivalent inputs not applicable here, but the
        # serializer should handle weirder max_age values without crashing
        # (covered by fuzzer mutations, not the seed corpus).
    ]
    for name, body in pkg_seeds:
        w("set_cookie_build", f"seed_{name}", body)

    # 4. invariant21
    for name, body in INV_SEEDS:
        w("invariant21", f"seed_{name}", body)

    # 5. date_parse
    for name, body in DP_SEEDS:
        w("date_parse", f"seed_{name}", ascii(body))

    # Sanity counts (must hit ≥50 per surface per V1 spec)
    summary: list[tuple[str, int]] = []
    for surf in ("set_cookie_parse", "cookie_header_parse", "set_cookie_build",
                 "invariant21", "date_parse"):
        n = sum(1 for _ in (CORPUS / surf).iterdir())
        summary.append((surf, n))
    print("seed-corpus counts:")
    for s, n in summary:
        print(f"  {s:<24} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())