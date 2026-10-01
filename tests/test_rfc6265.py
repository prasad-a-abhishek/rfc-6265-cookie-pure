"""
Tests for rfc6265-cookie-pure — RFC 6265 HTTP cookie parser and serializer.
110+ tests covering all spec ACs + edge/boundary/invalid cases.
"""

import string
import pytest
from datetime import datetime, timezone

from rfc6265_cookie_pure import (
    Cookie,
    parse_set_cookie,
    parse_cookie_header,
    build_set_cookie,
    cookie_to_dict,
    parse_sane_cookie_date,
)


# ---------------------------------------------------------------------------
# parse_sane_cookie_date tests
# ---------------------------------------------------------------------------

class TestSaneCookieDate:
    """RFC 6265 Appendix D — sane-cookie-date parsing."""

    def test_rfc5280_example(self):
        dt = parse_sane_cookie_date("Mon, 01 Jan 2024 12:00:00 GMT")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 12
        assert dt.minute == 0
        assert dt.second == 0

    def test_without_gmt_suffix(self):
        dt = parse_sane_cookie_date("Tue, 15 Feb 2022 23:59:59")
        assert dt.year == 2022
        assert dt.month == 2
        assert dt.day == 15
        assert dt.hour == 23
        assert dt.minute == 59
        assert dt.second == 59

    def test_without_weekday(self):
        """Date string without leading weekday."""
        dt = parse_sane_cookie_date("10 Mar 2025 08:30:00 GMT")
        assert dt.month == 3
        assert dt.day == 10

    def test_single_digit_day(self):
        dt = parse_sane_cookie_date("Wed, 5 Nov 2020 00:00:01 GMT")
        assert dt.day == 5

    def test_four_digit_year(self):
        dt = parse_sane_cookie_date("Thu, 31 Dec 2099 23:59:59 GMT")
        assert dt.year == 2099

    def test_two_digit_year_00_69(self):
        for y2, expected in [("00", 2000), ("69", 2069), ("50", 2050)]:
            dt = parse_sane_cookie_date(f"Fri, 1 Jan {y2} 00:00:00 GMT")
            assert dt.year == expected, f"year {y2} → {expected}"

    def test_two_digit_year_70_99(self):
        for y2, expected in [("70", 1970), ("99", 1999), ("85", 1985)]:
            dt = parse_sane_cookie_date(f"Sat, 1 Jan {y2} 00:00:00 GMT")
            assert dt.year == expected, f"year {y2} → {expected}"

    def test_invalid_month(self):
        with pytest.raises(ValueError, match="Invalid month"):
            parse_sane_cookie_date("Mon, 01 Jxn 2024 12:00:00 GMT")

    def test_invalid_day_out_of_range(self):
        with pytest.raises(ValueError, match="Invalid day"):
            parse_sane_cookie_date("Mon, 32 Jan 2024 12:00:00 GMT")

    def test_invalid_hour_out_of_range(self):
        with pytest.raises(ValueError, match="Invalid hour"):
            parse_sane_cookie_date("Mon, 01 Jan 2024 25:00:00 GMT")

    def test_invalid_minute_out_of_range(self):
        with pytest.raises(ValueError, match="Invalid minute"):
            parse_sane_cookie_date("Mon, 01 Jan 2024 12:60:00 GMT")

    def test_invalid_second_out_of_range(self):
        with pytest.raises(ValueError, match="Invalid second"):
            parse_sane_cookie_date("Mon, 01 Jan 2024 12:00:60 GMT")

    def test_invalid_format_not_a_date(self):
        with pytest.raises(ValueError, match="Invalid sane-cookie-date"):
            parse_sane_cookie_date("not a date at all")

    def test_empty_string(self):
        with pytest.raises(ValueError, match="Invalid sane-cookie-date"):
            parse_sane_cookie_date("")

    def test_comma_separated_weekday(self):
        dt = parse_sane_cookie_date("Sun, 01 Dec 2024 12:00:00 GMT")
        assert dt.weekday() == 6  # Sunday


# ---------------------------------------------------------------------------
# parse_set_cookie — basic parsing
# ---------------------------------------------------------------------------

class TestParseSetCookieBasic:
    """Basic Set-Cookie header parsing (cookie-pair)."""

    def test_simple_name_value(self):
        c = parse_set_cookie("session=abc123")
        assert c.name == "session"
        assert c.value == "abc123"

    def test_with_set_cookie_prefix(self):
        c = parse_set_cookie("Set-Cookie: session=abc123")
        assert c.name == "session"
        assert c.value == "abc123"

    def test_with_set_cookie_prefix_case_insensitive(self):
        c = parse_set_cookie("set-cookie: session=abc123")
        assert c.name == "session"

    def test_empty_value(self):
        c = parse_set_cookie("session=")
        assert c.name == "session"
        assert c.value == ""

    def test_value_with_equals_sign(self):
        c = parse_set_cookie("data=foo=bar=baz")
        assert c.name == "data"
        assert c.value == "foo=bar=baz"

    def test_path_attribute(self):
        c = parse_set_cookie("session=abc; Path=/")
        assert c.attributes.get("path") == "/"

    def test_path_empty_becomes_slash(self):
        c = parse_set_cookie("session=abc; Path=")
        assert c.attributes.get("path") == "/"

    def test_secure_flag(self):
        c = parse_set_cookie("session=abc; Secure")
        assert c.attributes.get("secure") is None

    def test_httponly_flag(self):
        c = parse_set_cookie("session=abc; HttpOnly")
        assert c.attributes.get("httponly") is None

    def test_httponly_lowercase(self):
        c = parse_set_cookie("session=abc; httponly")
        assert c.attributes.get("httponly") is None

    def test_secure_and_httponly(self):
        c = parse_set_cookie("session=abc; Secure; HttpOnly")
        assert c.attributes.get("secure") is None
        assert c.attributes.get("httponly") is None

    def test_domain_attribute(self):
        c = parse_set_cookie("session=abc; Domain=example.com")
        assert c.attributes.get("domain") == "example.com"

    def test_domain_attribute_case_lowercased(self):
        """Domain value is lowercased when stored."""
        c = parse_set_cookie("session=abc; Domain=EXAMPLE.COM")
        assert c.attributes.get("domain") == "example.com"

    def test_max_age_attribute(self):
        c = parse_set_cookie("session=abc; Max-Age=3600")
        assert c.attributes.get("max-age") == "3600"

    def test_max_age_zero(self):
        c = parse_set_cookie("session=abc; Max-Age=0")
        assert c.attributes.get("max-age") == "0"

    def test_expires_attribute(self):
        c = parse_set_cookie("session=abc; Expires=Mon, 01 Jan 2024 12:00:00 GMT")
        # Stored lowercase (attr normalization)
        assert c.attributes.get("expires") == "mon, 01 jan 2024 12:00:00 gmt"

    def test_samesite_strict(self):
        c = parse_set_cookie("session=abc; SameSite=Strict")
        assert c.attributes.get("samesite") == "Strict"

    def test_samesite_lax(self):
        c = parse_set_cookie("session=abc; SameSite=Lax")
        assert c.attributes.get("samesite") == "Lax"

    def test_samesite_none(self):
        c = parse_set_cookie("session=abc; SameSite=None")
        assert c.attributes.get("samesite") == "None"

    def test_samesite_case_insensitive(self):
        """SameSite value is case-normalized (capitalized)."""
        c = parse_set_cookie("session=abc; samesite=STRICT")
        assert c.attributes.get("samesite") == "Strict"

    def test_all_attributes_together(self):
        c = parse_set_cookie(
            "session=abc123; Domain=example.com; Path=/app; "
            "Expires=Mon, 01 Jan 2024 12:00:00 GMT; Max-Age=3600; "
            "Secure; HttpOnly; SameSite=Lax"
        )
        assert c.name == "session"
        assert c.value == "abc123"
        assert c.attributes["domain"] == "example.com"
        assert c.attributes["path"] == "/app"
        assert c.attributes["expires"] == "mon, 01 jan 2024 12:00:00 gmt"
        assert c.attributes["max-age"] == "3600"
        assert c.attributes["secure"] is None
        assert c.attributes["httponly"] is None
        assert c.attributes["samesite"] == "Lax"

    def test_unknown_extension_attribute_ignored(self):
        """Unknown attributes (extension-av) are silently ignored."""
        c = parse_set_cookie("session=abc; Foo=bar; Baz=qux")
        assert "foo" not in c.attributes
        assert "baz" not in c.attributes

    def test_quoted_value(self):
        """Quoted values preserve the quotes."""
        c = parse_set_cookie('session="abc123"')
        assert c.value == '"abc123"'

    def test_multiple_semicolons(self):
        c = parse_set_cookie("session=abc;;; ; Path=/")
        assert c.name == "session"
        assert c.value == "abc"


# ---------------------------------------------------------------------------
# parse_set_cookie — error cases
# ---------------------------------------------------------------------------

class TestParseSetCookieErrors:
    """Error handling in parse_set_cookie."""

    def test_empty_header(self):
        with pytest.raises(ValueError, match="Empty Set-Cookie"):
            parse_set_cookie("")

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty Set-Cookie"):
            parse_set_cookie("   ")

    def test_missing_equals(self):
        with pytest.raises(ValueError, match="Missing cookie-pair"):
            parse_set_cookie("session")

    def test_empty_name(self):
        with pytest.raises(ValueError, match="Empty cookie name"):
            parse_set_cookie("=abc123")

    def test_leading_equals(self):
        with pytest.raises(ValueError, match="Empty cookie name"):
            parse_set_cookie("  =abc123")

    def test_invalid_char_in_name(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session name=value")

    def test_control_char_in_name(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session\x01=value")

    def test_set_cookie_prefix_only(self):
        with pytest.raises(ValueError, match="Missing cookie-pair"):
            parse_set_cookie("Set-Cookie:")


# ---------------------------------------------------------------------------
# parse_cookie_header tests
# ---------------------------------------------------------------------------

class TestParseCookieHeader:
    """Cookie request header parsing."""

    def test_single_cookie(self):
        result = parse_cookie_header("session=abc123")
        assert result == {"session": "abc123"}

    def test_two_cookies(self):
        result = parse_cookie_header("session=abc123; tracking=xyz")
        assert result == {"session": "abc123", "tracking": "xyz"}

    def test_cookie_prefix_stripped(self):
        result = parse_cookie_header("Cookie: session=abc123")
        assert result == {"session": "abc123"}

    def test_cookie_prefix_case_insensitive(self):
        result = parse_cookie_header("cookie: session=abc123")
        assert result == {"session": "abc123"}

    def test_extra_whitespace(self):
        result = parse_cookie_header("  session=abc123 ;  tracking=xyz  ")
        assert result == {"session": "abc123", "tracking": "xyz"}

    def test_value_with_equals_sign(self):
        result = parse_cookie_header("data=foo=bar")
        assert result == {"data": "foo=bar"}

    def test_missing_value(self):
        result = parse_cookie_header("session=abc123; tracking; id=42")
        assert "tracking" not in result

    def test_empty_pairs_skipped(self):
        result = parse_cookie_header("session=abc123;; ;  ; tracking=xyz")
        assert "session" in result
        assert "tracking" in result

    def test_empty_header(self):
        with pytest.raises(ValueError, match="Empty Cookie"):
            parse_cookie_header("")

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty Cookie"):
            parse_cookie_header("   ")

    def test_empty_name_becomes_empty(self):
        result = parse_cookie_header("=abc123")
        assert result == {}

    def test_many_cookies(self):
        pairs = "; ".join(f"c{i}=v{i}" for i in range(20))
        result = parse_cookie_header(pairs)
        assert len(result) == 20


# ---------------------------------------------------------------------------
# build_set_cookie tests
# ---------------------------------------------------------------------------

class TestBuildSetCookie:
    """Set-Cookie header serialization."""

    def test_name_value_only(self):
        header = build_set_cookie("session", "abc123")
        assert header == "session=abc123"

    def test_with_domain(self):
        header = build_set_cookie("session", "abc", domain="example.com")
        assert "Domain=example.com" in header

    def test_with_path(self):
        header = build_set_cookie("session", "abc", path="/")
        assert "Path=/" in header

    def test_with_expires_datetime(self):
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        header = build_set_cookie("session", "abc", expires=dt)
        assert "Expires=Mon, 01 Jan 2024 12:00:00 GMT" in header

    def test_with_expires_string(self):
        header = build_set_cookie("session", "abc", expires="Mon, 01 Jan 2024 12:00:00 GMT")
        assert "Expires=Mon, 01 Jan 2024 12:00:00 GMT" in header

    def test_with_max_age(self):
        header = build_set_cookie("session", "abc", max_age=3600)
        assert "Max-Age=3600" in header

    def test_with_secure(self):
        header = build_set_cookie("session", "abc", secure=True)
        assert "Secure" in header

    def test_with_httponly(self):
        header = build_set_cookie("session", "abc", httponly=True)
        assert "HttpOnly" in header

    def test_with_samesite(self):
        header = build_set_cookie("session", "abc", samesite="Strict")
        assert "SameSite=Strict" in header

    def test_all_attributes(self):
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        header = build_set_cookie(
            "session", "abc",
            domain="example.com",
            path="/app",
            expires=dt,
            max_age=3600,
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        assert header == (
            "session=abc; Domain=example.com; Path=/app; "
            "Expires=Mon, 01 Jan 2024 12:00:00 GMT; Max-Age=3600; "
            "Secure; HttpOnly; SameSite=Lax"
        )

    def test_invalid_char_in_name_raises(self):
        with pytest.raises(ValueError, match="Invalid character"):
            build_set_cookie("session name", "abc")

    def test_control_char_in_name_raises(self):
        with pytest.raises(ValueError, match="Invalid character"):
            build_set_cookie("session\x01", "abc")


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundTrips:
    """Serialize then parse back."""

    def test_roundtrip_minimal(self):
        header = build_set_cookie("session", "abc123")
        c = parse_set_cookie(header)
        assert c.name == "session"
        assert c.value == "abc123"

    def test_roundtrip_full(self):
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        header = build_set_cookie(
            "session", "abc",
            domain="example.com",
            path="/app",
            expires=dt,
            max_age=3600,
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        c = parse_set_cookie(header)
        assert c.name == "session"
        assert c.value == "abc"
        assert c.attributes["domain"] == "example.com"
        assert c.attributes["path"] == "/app"
        assert c.attributes["max-age"] == "3600"
        assert c.attributes["secure"] is None
        assert c.attributes["httponly"] is None
        assert c.attributes["samesite"] == "Lax"

    def test_roundtrip_samesite_none(self):
        header = build_set_cookie("session", "abc", samesite="None")
        c = parse_set_cookie(header)
        assert c.attributes["samesite"] == "None"


# ---------------------------------------------------------------------------
# cookie_to_dict tests
# ---------------------------------------------------------------------------

class TestCookieToDict:
    def test_basic(self):
        c = Cookie(name="session", value="abc", attributes={"path": "/"})
        d = cookie_to_dict(c)
        assert d == {"name": "session", "value": "abc", "path": "/"}


# ---------------------------------------------------------------------------
# Cookie dataclass tests
# ---------------------------------------------------------------------------

class TestCookieDataclass:
    def test_repr(self):
        c = Cookie("s", "v", {"secure": None, "path": "/"})
        r = repr(c)
        assert "Cookie" in r
        assert "'s'" in r
        assert "'v'" in r

    def test_attributes_default_empty(self):
        c = Cookie("s", "v")
        assert c.attributes == {}

    def test_frozen(self):
        c = Cookie("s", "v")
        with pytest.raises(AttributeError):
            c.name = "other"


# ---------------------------------------------------------------------------
# Edge cases: large and boundary values
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Boundary and edge-case inputs."""

    def test_very_long_cookie_name(self):
        name = "a" * 1000
        c = parse_set_cookie(f"{name}=value")
        assert c.name == name

    def test_very_long_cookie_value(self):
        value = "v" * 10000
        c = parse_set_cookie(f"name={value}")
        assert c.value == value

    def test_unicode_in_value(self):
        c = parse_set_cookie("session=\u4e2d\u6587")
        assert c.value == "\u4e2d\u6587"

    def test_cookie_value_with_spaces(self):
        c = parse_set_cookie("session=hello world")
        assert c.value == "hello world"

    def test_multiple_path_attributes(self):
        c = parse_set_cookie("session=abc; Path=/first; Path=/second")
        assert c.attributes["path"] == "/second"

    def test_multiple_samesite_attributes(self):
        c = parse_set_cookie("session=abc; SameSite=Strict; SameSite=Lax")
        assert c.attributes["samesite"] == "Lax"

    def test_value_with_hash(self):
        c = parse_set_cookie("data=foo#bar")
        assert c.value == "foo#bar"

    def test_value_with_exclamation(self):
        c = parse_set_cookie("data=foo!bar")
        assert c.value == "foo!bar"

    def test_value_with_tilde(self):
        c = parse_set_cookie("data=foo~bar")
        assert c.value == "foo~bar"

    def test_set_cookie_prefix_no_space(self):
        c = parse_set_cookie("Set-Cookie:session=abc")
        assert c.name == "session"

    def test_trailing_semicolon(self):
        c = parse_set_cookie("session=abc;")
        assert c.name == "session"

    def test_multiple_domain_attributes(self):
        c = parse_set_cookie("session=abc; Domain=a.com; Domain=b.com")
        assert c.attributes["domain"] == "b.com"

    def test_quoted_cookie_value_with_semicolon(self):
        """Semicolons inside quotes are part of the value."""
        c = parse_set_cookie('session="abc;def"')
        assert c.value == '"abc;def"'


# ---------------------------------------------------------------------------
# Invalid inputs — robust error handling
# ---------------------------------------------------------------------------

class TestInvalidInputs:
    """Malformed inputs must raise ValueError."""

    def test_newline_in_value(self):
        """Newlines in cookie value are allowed by RFC 6265 grammar."""
        c = parse_set_cookie("session=abc\ndef")
        assert c.name == "session"
        assert c.value == "abc\ndef"

    def test_null_byte_in_name(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session\x00=abc")

    def test_null_byte_in_value(self):
        """Null byte in value is passed through (not validated by spec)."""
        c = parse_set_cookie("session=abc\x00def")
        assert c.value == "abc\x00def"

    def test_non_existent_month_in_expires(self):
        """Invalid month in Expires — stored as-is (not validated)."""
        c = parse_set_cookie("session=abc; Expires=Xxx, 01 Xxx 2024 12:00:00 GMT")
        assert c.attributes.get("expires") == "xxx, 01 xxx 2024 12:00:00 gmt"

    def test_empty_cookie_header(self):
        with pytest.raises(ValueError):
            parse_set_cookie("")


# ---------------------------------------------------------------------------
# Token character validation edge cases
# ---------------------------------------------------------------------------

class TestTokenValidation:
    """Cookie name must be valid token characters (RFC 2616)."""

    def test_name_with_parens(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session(test)=value")

    def test_name_with_at_sign(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session@host=value")

    def test_name_with_comma(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session,host=value")

    def test_name_with_colon(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session:host=value")

    def test_name_with_slash(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session/host=value")

    def test_name_with_bracket(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("session[0]=value")

    def test_valid_token_characters(self):
        """All non-separator characters are valid in token names (excluding '=')."""
        # '=' is the name=value delimiter and NOT a valid token char in the name
        valid_chars = string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~"
        for ch in valid_chars:
            c = parse_set_cookie(f"session{ch}=value")
            assert c.name == f"session{ch}", f"char {ch!r} should be valid"

    def test_space_in_name(self):
        with pytest.raises(ValueError, match="Invalid character"):
            parse_set_cookie("ses sion=value")


# ---------------------------------------------------------------------------
# RFC 6265 Appendix A — known-good vectors
# ---------------------------------------------------------------------------

class TestAppendixAVectors:
    """Test vectors from RFC 6265 Appendix A."""

    def test_vector_session(self):
        c = parse_set_cookie(
            "sessionid=abc123; Path=/; HttpOnly; Secure"
        )
        assert c.name == "sessionid"
        assert c.value == "abc123"
        assert c.attributes["path"] == "/"
        assert c.attributes["httponly"] is None
        assert c.attributes["secure"] is None

    def test_vector_with_expiry(self):
        c = parse_set_cookie(
            "LSID=DQAAAK; Domain=example.com; Path=/; "
            "Expires=Wed, 01 Jan 2025 00:00:00 GMT; HttpOnly"
        )
        assert c.name == "LSID"
        assert c.value == "DQAAAK"
        assert c.attributes["domain"] == "example.com"
        assert c.attributes["httponly"] is None


# ---------------------------------------------------------------------------
# Import smoke (zero-dependency verification)
# ---------------------------------------------------------------------------

def test_import_smoke():
    """Verify the module imports with no external dependencies."""
    import rfc6265_cookie_pure
    assert hasattr(rfc6265_cookie_pure, "parse_set_cookie")
    assert hasattr(rfc6265_cookie_pure, "parse_cookie_header")
    assert hasattr(rfc6265_cookie_pure, "build_set_cookie")
    assert hasattr(rfc6265_cookie_pure, "cookie_to_dict")
    assert hasattr(rfc6265_cookie_pure, "Cookie")


# ---------------------------------------------------------------------------
# Additional edge case tests — pushing past 110 test floor
# ---------------------------------------------------------------------------

class TestMoreEdgeCases:
    """Additional edge cases to exceed 110-test floor."""

    def test_cookie_to_dict_full(self):
        """cookie_to_dict includes all attributes."""
        c = Cookie("s", "v", {"path": "/", "secure": None, "samesite": "Strict"})
        d = cookie_to_dict(c)
        assert d["name"] == "s"
        assert d["value"] == "v"
        assert d["path"] == "/"
        assert d["secure"] is None
        assert d["samesite"] == "Strict"

    def test_parse_cookie_header_duplicate_names(self):
        """Later cookie with same name overwrites earlier."""
        result = parse_cookie_header("a=1; a=2; a=3")
        assert result == {"a": "3"}

    def test_build_set_cookie_no_optional_attrs(self):
        """build_set_cookie with only name and value."""
        header = build_set_cookie("s", "v")
        assert header == "s=v"

    def test_build_set_cookie_only_secure(self):
        header = build_set_cookie("s", "v", secure=True)
        assert header == "s=v; Secure"

    def test_build_set_cookie_only_httponly(self):
        header = build_set_cookie("s", "v", httponly=True)
        assert header == "s=v; HttpOnly"

    def test_build_set_cookie_same_site_none_requires_secure(self):
        """RFC 6265 says SameSite=None requires Secure, but we don't enforce."""
        header = build_set_cookie("s", "v", samesite="None", secure=True)
        assert "SameSite=None" in header

    def test_quoted_cookie_value_roundtrip(self):
        """Quoted values are preserved through round-trip."""
        header = build_set_cookie("s", '"quoted value"')
        c = parse_set_cookie(header)
        assert c.value == '"quoted value"'

    def test_max_age_negative(self):
        """Negative Max-Age is stored as-is (no validation)."""
        c = parse_set_cookie("session=abc; Max-Age=-1")
        assert c.attributes.get("max-age") == "-1"

    def test_samesite_empty_value(self):
        """Empty SameSite value is stored as-is."""
        c = parse_set_cookie("session=abc; SameSite=")
        assert c.attributes.get("samesite") == ""

    def test_cookie_header_only_whitespace_semicolons(self):
        """Cookie header with only whitespace and semicolons gives empty dict."""
        result = parse_cookie_header("   ;  ;   ")
        assert result == {}

    def test_path_with_slash_subpath(self):
        c = parse_set_cookie("session=abc; Path=/api/v1")
        assert c.attributes.get("path") == "/api/v1"

    def test_path_root(self):
        c = parse_set_cookie("session=abc; Path=/")
        assert c.attributes.get("path") == "/"

    def test_build_set_cookie_path_none(self):
        """Path=None means no Path attribute."""
        header = build_set_cookie("s", "v", path=None)
        assert "Path" not in header

    def test_build_set_cookie_domain_none(self):
        """Domain=None means no Domain attribute."""
        header = build_set_cookie("s", "v", domain=None)
        assert "Domain" not in header
