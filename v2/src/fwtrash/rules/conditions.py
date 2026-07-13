"""Condition classes for rule matching.

Re-exports from engine module for cleaner imports.
"""

from fwtrash.rules.engine import (
    Base64RegexCondition,
    CompoundCondition,
    Condition,
    LengthCondition,
    MatchResult,
    PlainCondition,
    RegexCondition,
)

__all__ = [
    "Condition",
    "RegexCondition",
    "Base64RegexCondition",
    "PlainCondition",
    "LengthCondition",
    "CompoundCondition",
    "MatchResult",
]
