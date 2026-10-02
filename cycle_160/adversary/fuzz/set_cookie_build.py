#!/usr/bin/env python3
"""Fuzz harness: build_set_cookie surface (8-attribute parametric serializer).

Surface covered: the public ``build_set_cookie(name, value, *, domain, path,
expires, max_age, secure, httponly, samesite) -> str`` entry point. The fuzzer
consumes name + value + 8 optional kwargs from the input and exercises the
serializer. Expected exceptions (ValueError on invalid token chars in name)
are swallowed; any uncaught exception is a libFuzzer crash.

Per Invariant 21, only ValueError is acceptable for str inputs.
"""
import sys
import atheris

with atheris.instrument_imports():
    from rfc6265_cookie_pure import build_set_cookie


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(128)
    value = fdp.ConsumeUnicodeNoSurrogates(4096)
    domain = fdp.ConsumeUnicodeNoSurrogates(128)
    path = fdp.ConsumeUnicodeNoSurrogates(128)
    expires = fdp.ConsumeUnicodeNoSurrogates(64)  # string-typed expires path
    max_age = fdp.ConsumeIntInRange(-(2**31), 2**31 - 1)
    secure = fdp.ConsumeBool()
    httponly = fdp.ConsumeBool()
    samesite = fdp.ConsumeUnicodeNoSurrogates(16)
    try:
        build_set_cookie(
            name,
            value,
            domain=domain if domain else None,
            path=path if path else None,
            expires=expires if expires else None,
            max_age=max_age,
            secure=secure,
            httponly=httponly,
            samesite=samesite if samesite else None,
        )
    except ValueError:
        # Documented contract: invalid token chars in name raise ValueError.
        return
    # Anything else is an Invariant 21 violation or a crash \u2014 do NOT swallow.


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()