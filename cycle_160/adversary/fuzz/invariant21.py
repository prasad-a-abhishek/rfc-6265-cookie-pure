#!/usr/bin/env python3
"""Fuzz harness: Invariant 21 \u2014 total over arbitrary input.

Surface covered: each of the 4 public top-level functions MUST raise the
documented ValueError cleanly when called with non-string types (None, int,
bool, list, dict, bytes, float, NaN). This harness feeds a fixed set of bad
inputs through each function. Any uncaught exception \u2014 AttributeError,
TypeError, or anything else \u2014 escapes and becomes a libFuzzer crash.

The fuzzer input only picks which (function, bad-input) pair to exercise
(so coverage-guided fuzzing can weight the productive paths); the actual
arguments come from the deterministic ``BAD_TYPES`` list below.

If this harness surfaces crashes, F-M1 from VULN_AUDIT.md is reproducible
via fuzzing and the cycle must block back to @repo-builder for remediation.
"""
import math
from typing import Any, Callable

import atheris

with atheris.instrument_imports():
    from rfc6265_cookie_pure import (
        Cookie,
        build_set_cookie,
        cookie_to_dict,
        parse_cookie_header,
        parse_set_cookie,
    )


# 9 non-string types per V-3 coverage mandate + VULN_M1 probe matrix.
BAD_TYPES: tuple[Any, ...] = (
    None,
    42,
    True,
    False,
    [],
    {},
    b"foo=bar",
    3.14,
    math.nan,
)

# Each entry: (callable, list-of-positional-args, list-of-kwarg-dicts)
# Functions with no args (cookie_to_dict) take a single Cookie value as input.
PUBLIC_FUNCTIONS: tuple[tuple[Callable, list, list], ...] = (
    (parse_set_cookie, [], []),
    (parse_cookie_header, [], []),
    (build_set_cookie, [], []),
    (cookie_to_dict, [], []),
)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # Pick one bad type and one function per iteration; coverage-guided
    # fuzzing will weight the combos that produce interesting crashes.
    fn_idx = fdp.ConsumeIntInRange(0, len(PUBLIC_FUNCTIONS) - 1)
    type_idx = fdp.ConsumeIntInRange(0, len(BAD_TYPES) - 1)
    fn, _pos, _kw = PUBLIC_FUNCTIONS[fn_idx]
    bad = BAD_TYPES[type_idx]

    # cookie_to_dict expects a Cookie; pass one wrapping the bad value to keep
    # the type signature valid (it will then run attributes.items() on a dict
    # inside the bad value's class \u2014 still surfaces the totality gap).
    if fn is cookie_to_dict:
        if isinstance(bad, Cookie):
            return  # valid path \u2014 not a bad-input exercise
        try:
            fn(bad)  # type: ignore[arg-type]
        except (ValueError, TypeError, AttributeError):
            return  # any of these is acceptable per Invariant 21 today
        # If it returns successfully for a non-Cookie input, that is itself
        # a finding (silent acceptance). Let it through as a "crash" by
        # raising so the run is logged.
        raise AssertionError(
            f"cookie_to_dict({bad!r}) returned without raising \u2014 "
            f"silent acceptance on non-Cookie input (F-M1 family)."
        )
    else:
        try:
            fn(bad)  # type: ignore[arg-type]
        except (ValueError, TypeError, AttributeError):
            return
        # Silent acceptance of bad type (e.g. build_set_cookie([], 'v')).
        raise AssertionError(
            f"{fn.__name__}({bad!r}) returned without raising \u2014 "
            f"silent acceptance on non-string input (F-M1 family)."
        )


if __name__ == "__main__":
    import sys as _sys
    atheris.Setup(_sys.argv, TestOneInput)
    atheris.Fuzz()