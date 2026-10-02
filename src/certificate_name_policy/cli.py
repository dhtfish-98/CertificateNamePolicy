"""Read one local certificate and print bounded JSON; no online modes."""

from __future__ import annotations

import argparse
import json

from . import __version__
from .policy import Report, evaluate_file


class _UsageError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Do not echo untrusted arguments or let usage errors resemble mismatch results.
        raise _UsageError("invalid_cli_arguments")


def main(argv: list[str] | None = None) -> int:
    """Exit 0 for name match, 1 for mismatch, 2 for OPEN/error. Trust always OPEN."""
    parser = _Parser(description="Local DNS/IP SAN name check; certificate trust stays OPEN.")
    parser.add_argument("certificate", help="one regular PEM/DER file; no symlinks")
    parser.add_argument("reference", help="expected fully qualified DNS name or bare IP")
    parser.add_argument("--kind", choices=("auto", "dns", "ip"), default="auto")
    parser.add_argument("--version", action="version", version=__version__)
    try:
        args = parser.parse_args(argv)
        report = evaluate_file(args.certificate, args.reference, kind=args.kind)
    except _UsageError:
        report = Report("OPEN", "MALFORMED", "invalid_cli_arguments")
    print(json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report.status]
