#!/usr/bin/env python3
"""Fuzz harness: parse_cookie_header surface (RFC 6265 \u00a75.4 cookie-pair grammar).

Surface covered: the public ``parse_cookie_header(header: str) -> dict`` entry
point. The fuzzer consumes a single unicode string from the input and exercises
the cookie-request parser. Expected exceptions (ValueError on empty header) are
swallowed; any uncaught exception is a libFuzzer crash.

Per Invariant 21, only ValueError is acceptable for str inputs.
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc6265_cookie_pure import parse_cookie_header


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Cookie request headers carry name=value pairs separated by ';' + SP.
    # Cap at 16KB to bound memory.
    arg = fdp.ConsumeUnicodeNoSurrogates(16384)
    try:
        parse_cookie_header(arg)
    except ValueError:
        # Documented contract: empty Cookie header raises ValueError.
        return
    # Anything else is an Invariant 21 violation or a crash \u2014 do NOT swallow.


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()