#!/usr/bin/env python3
"""Fuzz harness: parse_sane_cookie_date surface (RFC 6265 Appendix D date grammar).

Surface covered: the public ``parse_sane_cookie_date(date_str: str) -> datetime``
entry point. The fuzzer consumes a single unicode string from the input and
exercises the date parser across the three documented formats:

  - RFC 1123 (e.g. ``Sun, 06 Nov 1994 08:49:37 GMT``)
  - RFC 850  (e.g. ``Sunday, 06-Nov-94 08:49:37 GMT``)
  - asctime  (e.g. ``Sun Nov  6 08:49:37 1994``)

Expected exceptions (``ValueError`` on malformed input) are swallowed; any
uncaught exception is a libFuzzer crash. Per Invariant 21 (totality), only
``ValueError`` is acceptable — ``AttributeError`` / ``TypeError`` raised
against ``str`` inputs would indicate a real bug in the parser.

This surface is also exercised indirectly by ``parse_set_cookie`` when the
``expires=`` attribute is parsed, so a crash here propagates to T3's deeper
campaigns.
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc6265_cookie_pure import parse_sane_cookie_date


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Cookie date strings are short in practice; cap at 4KB to keep coverage
    # on realistic inputs (RFC 1123/850/asctime strings are < 64 bytes).
    arg = fdp.ConsumeUnicodeNoSurrogates(4096)
    try:
        parse_sane_cookie_date(arg)
    except ValueError:
        # Documented contract: unrecognised date strings raise ValueError.
        return
    # Anything else is an Invariant 21 violation or a crash — do NOT swallow.


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
