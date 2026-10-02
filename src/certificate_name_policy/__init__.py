"""Offline DNS/IP SAN checks. A name match never establishes certificate trust."""

from .policy import Limits, Report, evaluate_bytes, evaluate_file

__all__ = ["Limits", "Report", "evaluate_bytes", "evaluate_file"]
__version__ = "0.1.0"
