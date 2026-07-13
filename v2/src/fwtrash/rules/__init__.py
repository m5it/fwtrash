"""Rule engine for detecting malicious log entries."""

from fwtrash.rules.engine import RuleEngine, RuleCondition
from fwtrash.rules.conditions import (
    RegexCondition,
    LengthCondition,
    Base64RegexCondition,
    CompoundCondition,
)

__all__ = [
    "RuleEngine",
    "RuleCondition",
    "RegexCondition",
    "LengthCondition", 
    "Base64RegexCondition",
    "CompoundCondition",
]
