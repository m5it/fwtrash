"""Rule engine for detecting malicious log entries.

Provides typed condition classes with compilation/caching for performance.
Replaces v0.6's string-based rule matching with extensible class hierarchy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, ClassVar, TypeVar

from fwtrash.core.models import ConditionType, LogEntry, Rule, RuleCondition, RuleMetadata

T = TypeVar("T", bound="Condition")


class MatchResult:
    """Result of a condition evaluation."""
    
    def __init__(
        self,
        matched: bool,
        confidence: float = 0.0,
        matched_value: Any = None,
        metadata: dict[str, Any] | None = None
    ) -> None:
        self.matched = matched
        self.confidence = confidence
        self.matched_value = matched_value
        self.metadata = metadata or {}
    
    def __bool__(self) -> bool:
        return self.matched
    
    @classmethod
    def no_match(cls) -> "MatchResult":
        return cls(matched=False, confidence=0.0)
    
    @classmethod
    def match(cls, confidence: float = 1.0, **kwargs: Any) -> "MatchResult":
        return cls(matched=True, confidence=confidence, **kwargs)


class Condition(ABC):
    """Abstract base class for all rule conditions.
    
    Conditions are stateless and can be cached/reused across rules.
    """
    
    condition_type: ClassVar[ConditionType]
    
    def __init__(self, field: str, negate: bool = False) -> None:
        self.field = field
        self.negate = negate
        self._compiled: Any = None
    
    @abstractmethod
    def compile(self) -> Any:
        """Compile the condition for faster matching.
        
        Returns the compiled representation (regex pattern, etc.)
        """
        pass
    
    @abstractmethod
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Evaluate condition against a field value."""
        pass
    
    def evaluate(self, entry: LogEntry) -> MatchResult:
        """Evaluate this condition against a log entry."""
        # Get field value
        value = self._get_field_value(entry)
        if value is None:
            return MatchResult.no_match()
        
        # Evaluate
        result = self._evaluate(value, entry)
        
        # Apply negation
        if self.negate:
            result.matched = not result.matched
            result.confidence = 1.0 - result.confidence
        
        return result
    
    def _get_field_value(self, entry: LogEntry) -> Any:
        """Extract field value from entry."""
        # Check parsed_fields first
        if self.field in entry.parsed_fields:
            return entry.parsed_fields[self.field]
        
        # Check direct attributes
        return getattr(entry, self.field, None)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "field": self.field,
            "type": self.condition_type.value,
            "negate": self.negate
        }
    
    @classmethod
    @abstractmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Deserialize from dictionary."""
        pass
    
    @classmethod
    def from_rule_condition(cls, rc: RuleCondition) -> "Condition":
        """Create appropriate Condition subclass from RuleCondition."""
        condition_map: dict[ConditionType, type[Condition]] = {
            ConditionType.REGEX: RegexCondition,
            ConditionType.BASE64_REGEX: Base64RegexCondition,
            ConditionType.PLAIN: PlainCondition,
            ConditionType.LENGTH_GTE: LengthCondition,
            ConditionType.LENGTH_GT: LengthCondition,
            ConditionType.LENGTH_LTE: LengthCondition,
            ConditionType.LENGTH_LT: LengthCondition,
            ConditionType.LENGTH_EQ: LengthCondition,
        }
        
        condition_class = condition_map.get(rc.condition_type)
        if condition_class is None:
            raise ValueError(f"Unknown condition type: {rc.condition_type}")
        
        # Handle length conditions specially
        if issubclass(condition_class, LengthCondition):
            return LengthCondition.from_rule_condition(rc)
        
        return condition_class.from_rule_condition(rc)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(field={self.field}, negate={self.negate})"


class RegexCondition(Condition):
    """Regex pattern matching condition (Type 2 in v0.6)."""
    
    condition_type = ConditionType.REGEX
    
    def __init__(
        self,
        field: str,
        pattern: str,
        negate: bool = False,
        case_sensitive: bool = False
    ) -> None:
        super().__init__(field, negate)
        self.pattern = pattern
        self.case_sensitive = case_sensitive
    
    def compile(self) -> re.Pattern[str]:
        """Compile regex pattern."""
        if self._compiled is None:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled
    
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Match value against regex."""
        if not isinstance(value, str):
            value = str(value)
        
        compiled = self.compile()
        match = compiled.search(value)
        
        if match:
            return MatchResult.match(
                confidence=1.0,
                matched_value=match.group(0),
                metadata={
                    "groups": match.groups(),
                    "groupdict": match.groupdict()
                }
            )
        return MatchResult.no_match()
    
    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["pattern"] = self.pattern
        data["case_sensitive"] = self.case_sensitive
        return data
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegexCondition":
        return cls(
            field=data["field"],
            pattern=data["pattern"],
            negate=data.get("negate", False),
            case_sensitive=data.get("case_sensitive", False)
        )
    
    @classmethod
    def from_rule_condition(cls, rc: RuleCondition) -> "RegexCondition":
        return cls(
            field=rc.field,
            pattern=rc.pattern,
            negate=rc.negate,
            case_sensitive=False
        )


class Base64RegexCondition(RegexCondition):
    """Base64 decode then regex match (Type 1 in v0.6)."""
    
    condition_type = ConditionType.BASE64_REGEX
    
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Decode base64 then match."""
        if not isinstance(value, str):
            value = str(value)
        
        # Try to decode base64
        try:
            # Add padding if needed
            padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            return MatchResult.no_match()
        
        # Run regex on decoded value
        compiled = self.compile()
        match = compiled.search(decoded)
        
        if match:
            return MatchResult.match(
                confidence=1.0,
                matched_value=match.group(0),
                metadata={
                    "decoded": decoded,
                    "groups": match.groups(),
                    "groupdict": match.groupdict()
                }
            )
        return MatchResult.no_match()
    
    @classmethod
    def from_rule_condition(cls, rc: RuleCondition) -> "Base64RegexCondition":
        return cls(
            field=rc.field,
            pattern=rc.pattern,
            negate=rc.negate,
            case_sensitive=False
        )


class PlainCondition(Condition):
    """Exact string match condition (Type 3 in v0.6)."""
    
    condition_type = ConditionType.PLAIN
    
    def __init__(
        self,
        field: str,
        value: str,
        negate: bool = False,
        case_sensitive: bool = False
    ) -> None:
        super().__init__(field, negate)
        self.value = value
        self.case_sensitive = case_sensitive
    
    def compile(self) -> str:
        """Return normalized value."""
        if not self.case_sensitive:
            return self.value.lower()
        return self.value
    
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Exact string comparison."""
        if not isinstance(value, str):
            value = str(value)
        
        if self.case_sensitive:
            matched = self.value == value
        else:
            matched = self.value.lower() == value.lower()
        
        if matched:
            return MatchResult.match(confidence=1.0, matched_value=value)
        return MatchResult.no_match()
    
    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["value"] = self.value
        data["case_sensitive"] = self.case_sensitive
        return data
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlainCondition":
        return cls(
            field=data["field"],
            value=data["value"],
            negate=data.get("negate", False),
            case_sensitive=data.get("case_sensitive", False)
        )
    
    @classmethod
    def from_rule_condition(cls, rc: RuleCondition) -> "PlainCondition":
        return cls(
            field=rc.field,
            value=rc.pattern,
            negate=rc.negate,
            case_sensitive=False
        )


class LengthCondition(Condition):
    """Length comparison conditions (Types 4-8 in v0.6)."""
    
    condition_type = ConditionType.LENGTH_GTE  # Default, overridden per instance
    
    _OPERATORS: ClassVar[dict[ConditionType, callable]] = {
        ConditionType.LENGTH_GTE: lambda a, b: a >= b,
        ConditionType.LENGTH_GT: lambda a, b: a > b,
        ConditionType.LENGTH_LTE: lambda a, b: a <= b,
        ConditionType.LENGTH_LT: lambda a, b: a < b,
        ConditionType.LENGTH_EQ: lambda a, b: a == b,
    }
    
    def __init__(
        self,
        field: str,
        length: int,
        operator_type: ConditionType,
        negate: bool = False
    ) -> None:
        super().__init__(field, negate)
        self.length = length
        self.operator_type = operator_type
        self._operator = self._OPERATORS.get(operator_type)
        if self._operator is None:
            raise ValueError(f"Invalid length operator: {operator_type}")
    
    def compile(self) -> int:
        """Return target length."""
        return self.length
    
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Compare value length."""
        if isinstance(value, (list, dict, str, bytes)):
            actual_len = len(value)
        else:
            actual_len = len(str(value))
        
        if self._operator(actual_len, self.length):
            return MatchResult.match(
                confidence=1.0,
                matched_value=actual_len,
                metadata={"expected": self.length, "actual": actual_len}
            )
        return MatchResult.no_match()
    
    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["length"] = self.length
        data["operator"] = self.operator_type.value
        return data
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LengthCondition":
        return cls(
            field=data["field"],
            length=data["length"],
            operator_type=ConditionType(data["operator"]),
            negate=data.get("negate", False)
        )
    
    @classmethod
    def from_rule_condition(cls, rc: RuleCondition) -> "LengthCondition":
        # Map condition type to operator
        operator_map = {
            ConditionType.LENGTH_GTE: ConditionType.LENGTH_GTE,
            ConditionType.LENGTH_GT: ConditionType.LENGTH_GT,
            ConditionType.LENGTH_LTE: ConditionType.LENGTH_LTE,
            ConditionType.LENGTH_LT: ConditionType.LENGTH_LT,
            ConditionType.LENGTH_EQ: ConditionType.LENGTH_EQ,
        }
        
        op = operator_map.get(rc.condition_type, ConditionType.LENGTH_GTE)
        
        return cls(
            field=rc.field,
            length=rc.length_value or 0,
            operator_type=op,
            negate=rc.negate
        )


class CompoundCondition(Condition):
    """Logical combination of multiple conditions (AND/OR)."""
    
    # Not a real condition type, used internally
    condition_type = ConditionType.REGEX  # Placeholder
    
    def __init__(
        self,
        conditions: list[Condition],
        operator: str = "AND",
        negate: bool = False
    ) -> None:
        super().__init__("", negate)  # No single field
        self.conditions = conditions
        self.operator = operator.upper()  # AND or OR
    
    def compile(self) -> list[Condition]:
        """Compile all sub-conditions."""
        for c in self.conditions:
            c.compile()
        return self.conditions
    
    def _evaluate(self, value: Any, entry: LogEntry) -> MatchResult:
        """Evaluate all sub-conditions."""
        results = [c.evaluate(entry) for c in self.conditions]
        
        if self.operator == "AND":
            matched = all(r.matched for r in results)
        else:  # OR
            matched = any(r.matched for r in results)
        
        # Calculate aggregate confidence
        confidences = [r.confidence for r in results]
        if self.operator == "AND":
            confidence = min(confidences) if confidences else 0.0
        else:
            confidence = max(confidences) if confidences else 0.0
        
        if matched:
            return MatchResult.match(
                confidence=confidence,
                metadata={
                    "operator": self.operator,
                    "sub_results": results
                }
            )
        return MatchResult.no_match()
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "compound",
            "operator": self.operator,
            "negate": self.negate,
            "conditions": [c.to_dict() for c in self.conditions]
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CompoundCondition":
        # Deserialize sub-conditions
        conditions = []
        for c_data in data["conditions"]:
            c_type = ConditionType(c_data["type"])
            c = Condition.from_rule_condition(
                RuleCondition(field=c_data["field"], condition_type=c_type, pattern=c_data.get("pattern", ""))
            )
            conditions.append(c)
        
        return cls(
            conditions=conditions,
            operator=data.get("operator", "AND"),
            negate=data.get("negate", False)
        )


class RuleEngine:
    """Compiled rule engine with caching."""
    
    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._compiled_conditions: dict[str, list[Condition]] = {}
        self._condition_cache: dict[str, Condition] = {}
    
    def load_rules(self, rules: list[Rule]) -> None:
        """Load and compile rules."""
        self._rules = rules
        self._compiled_conditions = {}
        
        for rule in rules:
            conditions = []
            for rc in rule.conditions:
                cache_key = self._condition_key(rc)
                
                # Check cache
                if cache_key in self._condition_cache:
                    condition = self._condition_cache[cache_key]
                else:
                    condition = Condition.from_rule_condition(rc)
                    condition.compile()
                    self._condition_cache[cache_key] = condition
                
                conditions.append(condition)
            
            self._compiled_conditions[rule.rule_id] = conditions
    
    def _condition_key(self, rc: RuleCondition) -> str:
        """Generate cache key for a condition."""
        key_data = f"{rc.field}:{rc.condition_type.value}:{rc.pattern}:{rc.negate}"
        return hashlib.md5(key_data.encode()).hexdigest()[:16]
    
    def evaluate(self, entry: LogEntry) -> list[tuple[Rule, float]]:
        """Evaluate all rules against an entry.
        
        Returns list of (rule, confidence) tuples for matched rules.
        """
        matches = []
        
        for rule in self._rules:
            if not rule.metadata.enabled:
                continue
            
            conditions = self._compiled_conditions.get(rule.rule_id, [])
            if not conditions:
                continue
            
            # Evaluate all conditions (AND logic)
            all_match = True
            min_confidence = 1.0
            
            for condition in conditions:
                result = condition.evaluate(entry)
                if not result.matched:
                    all_match = False
                    break
                min_confidence = min(min_confidence, result.confidence)
            
            if all_match and rule.matches_confidence(min_confidence):
                matches.append((rule, min_confidence))
        
        return matches
    
    def load_from_json(self, json_path: str) -> None:
        """Load rules from JSON file (v0.6 format compatible)."""
        with open(json_path) as f:
            data = json.load(f)
        
        rules = []
        for item in data:
            # v0.6 format: list of condition objects per rule
            if isinstance(item, list):
                conditions = []
                for cond_data in item:
                    rc = RuleCondition(
                        field=cond_data.get("key", ""),
                        condition_type=ConditionType(
                            self._map_type(cond_data.get("type", 2))
                        ),
                        pattern=cond_data.get("data", ""),
                        bruteforce_key=cond_data.get("bruteforce_count_key")
                    )
                    conditions.append(rc)
                
                rule = Rule(
                    conditions=conditions,
                    metadata=RuleMetadata(
                        name=cond_data.get("name", "Unnamed Rule"),
                        description=cond_data.get("description", "")
                    )
                )
                rules.append(rule)
        
        self.load_rules(rules)
    
    def _map_type(self, v06_type: int) -> str:
        """Map v0.6 type numbers to ConditionType."""
        mapping = {
            1: "base64_regex",
            2: "regex",
            3: "plain",
            4: "length_gte",
            5: "length_gt",
            6: "length_lte",
            7: "length_lt",
            8: "length_eq",
        }
        return mapping.get(v06_type, "regex")
    
    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "rules_loaded": len(self._rules),
            "conditions_cached": len(self._condition_cache),
            "memory_kb": len(self._condition_cache) * 2  # Rough estimate
        }
