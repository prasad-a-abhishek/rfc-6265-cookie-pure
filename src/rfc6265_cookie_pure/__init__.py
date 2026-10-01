"""
rfc6265-cookie-pure — Zero-dependency RFC 6265 HTTP cookie parser and serializer.

Public API:
    parse_set_cookie(header: str) -> Cookie
    parse_cookie_header(header: str) -> dict[str, str]
    build_set_cookie(name: str, value: str, *, domain: str | None = ..., ...)
    cookie_to_dict(cookie: Cookie) -> dict

RFC 6265: https://www.rfc-editor.org/rfc/rfc6265
"""

from __future__ import annotations

import re
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Cookie:
    """Represents a parsed Set-Cookie header."""
    name: str
    value: str
    attributes: dict[str, str | None] = field(default_factory=dict)
    # attribute keys stored lowercase: domain, path, expires, max-age,
    # secure, httponly, samesite. Value is None for flags (Secure, HttpOnly).

    def __repr__(self) -> str:
        attrs = ", ".join(
            f"{k}={v!r}" if v is not None else k
            for k, v in sorted(self.attributes.items())
        )
        return f"Cookie({self.name!r}, {self.value!r}, {attrs})"


# ---------------------------------------------------------------------------
# Token / value grammar (RFC 6265 Section 5.4 + RFC 2616 token definition)
# ---------------------------------------------------------------------------

# token = 1*<any CHAR except CTLs or separators>
# separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <">
#              | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
TOKEN_SEPARATORS = frozenset("()<>@,;:\\\"/[]?={} \t")

CONTROL_CHARS = frozenset(map(chr, range(0x20)))  # All control characters

def _is_token_char(char: str) -> bool:
    """Return True if char is a valid token character per RFC 2616."""
    if char in TOKEN_SEPARATORS:
        return False
    if char in CONTROL_CHARS:
        return False
    return True


def _tokenize(s: str) -> list[str]:
    """Split a string into tokens (semicolon/comma separated)."""
    return [t.strip() for t in re.split(r"[;,]", s)]


# ---------------------------------------------------------------------------
# sane-cookie-date (RFC 6265 Appendix D — RFC 5322 date with restrictions)
# ---------------------------------------------------------------------------

# Weekday and month names from RFC 5322 / RFC 6265 Appendix D
_WEEKDAY = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_WEEKDAY_LONG = ["Monday", "Tuesday", "Wednesday", "Thursday",
                 "Friday", "Saturday", "Sunday"]
_MONTH = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_MONTH_LONG = ["January", "February", "March", "April", "May", "June",
               "July", "August", "September", "October", "November", "December"]

# Appendix D date format: "Mon, DD Mon YYYY HH:MM:SS GMT" (with or without weekday)
_DATE_RE = re.compile(
    r"(?:(?P<weekday>[A-Za-z]{3}),?\s+)?"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<month>[A-Za-z]{3})\s+"
    r"(?P<year>\d{2,4})\s+"
    r"(?P<hour>\d{2}):"
    r"(?P<minute>\d{2}):"
    r"(?P<second>\d{2})"
    r"(?:\s*GMT)?",
    re.ASCII
)

def _parse_month(mon: str) -> int:
    try:
        return _MONTH.index(mon.capitalize()[:3]) + 1
    except ValueError:
        raise ValueError(f"Invalid month: {mon!r}")


def parse_sane_cookie_date(date_str: str) -> datetime:
    """
    Parse a sane-cookie-date string (RFC 6265 Appendix D) into a datetime.

    Raises ValueError if the string is not a valid date.
    """
    m = _DATE_RE.match(date_str.strip())
    if not m:
        raise ValueError(f"Invalid sane-cookie-date: {date_str!r}")

    day = int(m.group("day"))
    mon = _parse_month(m.group("month"))
    year = int(m.group("year"))

    # Normalize 2-digit years
    if 0 <= year <= 69:
        year += 2000
    elif 70 <= year <= 99:
        year += 1900

    hour = int(m.group("hour"))
    minute = int(m.group("minute"))
    second = int(m.group("second"))

    # Basic range validation
    if not (1 <= day <= 31):
        raise ValueError(f"Invalid day: {day}")
    if not (0 <= hour <= 23):
        raise ValueError(f"Invalid hour: {hour}")
    if not (0 <= minute <= 59):
        raise ValueError(f"Invalid minute: {minute}")
    if not (0 <= second <= 59):
        raise ValueError(f"Invalid second: {second}")

    try:
        return datetime(year, mon, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(f"Invalid date: {e}") from e


# ---------------------------------------------------------------------------
# Set-Cookie header parser
# ---------------------------------------------------------------------------

def _parse_attributes(attrs: list[str]) -> dict[str, str | None]:
    """
    Parse the attribute list of a Set-Cookie header.

    Returns a dict with lowercase attribute names as keys.
    Flags (Secure, HttpOnly) have value None.
    """
    result: dict[str, str | None] = {}

    for attr in attrs:
        attr = attr.strip()
        if not attr:
            continue
        attr_lower = attr.lower()

        if attr_lower == "secure":
            result["secure"] = None
        elif attr_lower == "httponly":
            result["httponly"] = None
        elif attr_lower.startswith("domain="):
            result["domain"] = attr_lower.split("=", 1)[1]
        elif attr_lower.startswith("path="):
            raw_path = attr_lower.split("=", 1)[1]
            # Per RFC 6265, Path cannot be empty string; use "/" if absent
            result["path"] = raw_path if raw_path else "/"
        elif attr_lower.startswith("expires="):
            result["expires"] = attr_lower.split("=", 1)[1]
        elif attr_lower.startswith("max-age="):
            result["max-age"] = attr_lower.split("=", 1)[1]
        elif attr_lower.startswith("samesite="):
            raw_samesite = attr_lower.split("=", 1)[1]
            # SameSite value must be Strict, Lax, or None (case-insensitive)
            result["samesite"] = raw_samesite.capitalize()
        else:
            # Per spec, unknown attributes are ignored (extension-av)
            pass

    return result


def _split_cookie_string(s: str) -> list[str]:
    """
    Split a set-cookie-string on unquoted semicolons.
    Handles quoted cookie values (DQUOTE ... DQUOTE) correctly.
    RFC 6265 grammar: cookie-pair *( ";" SP cookie-av )
    """
    result: list[str] = []
    current = ""
    in_quotes = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '"':
            in_quotes = not in_quotes
            current += ch
        elif ch == ';' and not in_quotes:
            result.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    if current.strip():
        result.append(current.strip())
    return result


def parse_set_cookie(header: str) -> Cookie:
    """
    Parse a Set-Cookie header string into a Cookie namedtuple.

    Args:
        header: The full "Set-Cookie: ..." header value (without the prefix).

    Returns:
        Cookie(name, value, attributes)

    Raises:
        ValueError: If the header does not contain a valid cookie-pair.

    Examples:
        >>> c = parse_set_cookie("session=abc123; Path=/; HttpOnly; SameSite=Lax")
        >>> c.name
        'session'
        >>> c.value
        'abc123'
        >>> c.attributes["samesite"]
        'Lax'
    """
    if not header or not header.strip():
        raise ValueError("Empty Set-Cookie header")

    # Strip optional "Set-Cookie:" prefix
    stripped = re.sub(r"^Set-Cookie:\s*", "", header, flags=re.IGNORECASE)

    parts = _split_cookie_string(stripped)

    # First part must be cookie-pair: name=value
    if not parts or "=" not in parts[0]:
        raise ValueError(f"Missing cookie-pair in Set-Cookie header: {header!r}")

    cookie_pair = parts[0]
    name_eq, _, value_part = cookie_pair.partition("=")
    if not name_eq:
        raise ValueError(f"Empty cookie name in: {header!r}")
    name = name_eq.strip()
    value = value_part.rstrip()

    # Validate name is a valid token
    for ch in name:
        if not _is_token_char(ch):
            raise ValueError(f"Invalid character {ch!r} in cookie name {name!r}")

    # Parse remaining semicolon-separated attributes
    attributes = _parse_attributes(parts[1:])

    return Cookie(name=name, value=value, attributes=attributes)


# ---------------------------------------------------------------------------
# Cookie request header parser
# ---------------------------------------------------------------------------

def parse_cookie_header(header: str) -> dict[str, str]:
    """
    Parse a Cookie request header into a dict of name→value.

    Args:
        header: The full "Cookie: ..." header value (without the prefix).

    Returns:
        Dict mapping cookie names to values.

    Raises:
        ValueError: If the header is empty or malformed.

    Examples:
        >>> parse_cookie_header("session=abc123; tracking=xyz")
        {'session': 'abc123', 'tracking': 'xyz'}
    """
    if not header or not header.strip():
        raise ValueError("Empty Cookie header")

    # Strip optional "Cookie:" prefix
    header = re.sub(r"^Cookie:\s*", "", header, flags=re.IGNORECASE)

    result: dict[str, str] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            # Per spec, cookies without = sign are ignored in the cookie-string
            continue
        name, _, value = part.partition("=")
        if not name.strip():
            continue
        result[name.strip()] = value.strip()

    return result


# ---------------------------------------------------------------------------
# Set-Cookie serializer
# ---------------------------------------------------------------------------

def build_set_cookie(
    name: str,
    value: str,
    *,
    domain: str | None = None,
    path: str | None = None,
    expires: datetime | str | None = None,
    max_age: int | None = None,
    secure: bool = False,
    httponly: bool = False,
    samesite: str | None = None,
) -> str:
    """
    Serialize a cookie into a Set-Cookie header string.

    Args:
        name: Cookie name (must be a valid token).
        value: Cookie value.
        domain: Domain attribute.
        path: Path attribute.
        expires: Expiry date (datetime or ISO date string).
        max_age: Max-Age in seconds (int).
        secure: Secure flag.
        httponly: HttpOnly flag.
        samesite: SameSite value ("Strict", "Lax", or "None").

    Returns:
        A "name=value; ..." Set-Cookie header string.

    Raises:
        ValueError: If name is not a valid token.

    Examples:
        >>> build_set_cookie("session", "abc123", path="/", samesite="Strict")
        'session=abc123; Path=/; SameSite=Strict'
    """
    # Validate name
    for ch in name:
        if not _is_token_char(ch):
            raise ValueError(f"Invalid character {ch!r} in cookie name {name!r}")

    parts = [f"{name}={value}"]

    if domain is not None:
        parts.append(f"Domain={domain}")
    if path is not None:
        parts.append(f"Path={path}")
    if expires is not None:
        if isinstance(expires, datetime):
            parts.append(f"Expires={_format_http_date(expires)}")
        else:
            parts.append(f"Expires={expires}")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    if secure:
        parts.append("Secure")
    if httponly:
        parts.append("HttpOnly")
    if samesite is not None:
        parts.append(f"SameSite={samesite}")

    return "; ".join(parts)


def _format_http_date(dt: datetime) -> str:
    """Format a datetime as an RFC 5322 / HTTP date (UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    weekday = _WEEKDAY[dt.weekday()]
    month = _MONTH[dt.month - 1]
    return f"{weekday}, {dt.day:02d} {month} {dt.year} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} GMT"


# ---------------------------------------------------------------------------
# Convenience utilities
# ---------------------------------------------------------------------------

def cookie_to_dict(cookie: Cookie) -> dict:
    """
    Convert a Cookie into a flat dict.

    The 'name' and 'value' keys are top-level; attributes are prefixed
    with their original lowercase names.
    """
    result: dict = {"name": cookie.name, "value": cookie.value}
    for k, v in cookie.attributes.items():
        result[k] = v
    return result


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    "Cookie",
    "parse_set_cookie",
    "parse_cookie_header",
    "build_set_cookie",
    "cookie_to_dict",
    "parse_sane_cookie_date",
]
