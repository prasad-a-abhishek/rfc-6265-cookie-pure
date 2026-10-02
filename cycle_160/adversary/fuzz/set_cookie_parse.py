#!/usr/bin/env python3
"""Fuzz harness: parse_set_cookie surface (RFC 6265 \u00a74.1 Set-Cookie grammar).

Surface covered: the public ``parse_set_cookie(header: str) -> Cookie`` entry
point. The fuzzer consumes a single unicode string from the input and exercises
the parser. Expected exceptions (ValueError on empty/malformed input) are
swallowed; any uncaught exception is a libFuzzer crash.

Per Invariant 21 (totality), only ValueError is acceptable. AttributeError /
TypeError raised against str inputs would indicate a real bug in the parser.
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc6265_cookie_pure import parse_set_cookie


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Set-Cookie headers can be arbitrarily long; cap at 16KB.
    arg = fdp.ConsumeUnicodeNoSurrogates(16384)
    try:
        parse_set_cookie(arg)
    except ValueError:
        # Documented contract: empty / malformed Set-Cookie raises ValueError.
        return
    # Anything else is an Invariant 21 violation or a crash \u2014 do NOT swallow.


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()