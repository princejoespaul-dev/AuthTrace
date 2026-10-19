"""Compatibility CLI for the policy-driven AuthTrace regression pipeline.

Use the same diff, validation, mapping, selected-test runner, and evidence schema
as the dashboard instead of maintaining a separate fixed test execution path.
"""
from __future__ import annotations

import sys
from collections.abc import Sequence

from authtrace_pipeline import main as pipeline_main


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the default proposal's selected regression tests and save evidence."""
    args = [
        "--execute",
        "--report", "reports/latest.json",
        "--dashboard", "reports/dashboard.html",
    ]
    args.extend(sys.argv[1:] if argv is None else argv)
    return pipeline_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
