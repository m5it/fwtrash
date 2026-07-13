"""Unit tests for rule conditions."""

import base64
import re
from datetime import datetime

import pytest

from fwtrash.core.models import ConditionType, LogEntry, RuleCondition
from fwtrash.rules.engine import (
    Base64RegexCondition,
    CompoundCondition,
    LengthCondition,
    MatchResult,
    PlainCondition,
    RegexCondition,
)


class TestMatchResult:
    """Test MatchResult class."""
    
    def test_bool_conversion(self) -> None:
        assert bool(MatchResult(matched=True))
        assert not bool(MatchResult(matched=False))
    
    def test_no_match_factory(self) -> None:
        result = MatchResult.no_match()
        assert not result.matched
        assert result.confidence == 0.0
    
    def test_match_factory(self) -> None:
        result = MatchResult.match(confidence=0.8, matched_value="test")
        assert result.matched
        assert result.confidence == 0.8
        assert result.matched_value == "test"


class TestRegexCondition:
    """Test RegexCondition."""
    
    def test_basic_match(self) -> None:
        cond = RegexCondition("path", r"/admin")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/admin/login"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
        assert result.confidence == 1.0
        assert result.matched_value == "/admin"
    
    def test_no_match(self) -> None:
        cond = RegexCondition("path", r"/admin")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/home"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_case_insensitive(self) -> None:
        cond = RegexCondition("ua", r"bot", case_sensitive=False)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"ua": "BadBot/1.0"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_negation(self) -> None:
        cond = RegexCondition("path", r"/admin", negate=True)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/home"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched  # Negated: no match becomes match
    
    def test_missing_field(self) -> None:
        cond = RegexCondition("nonexistent", r"test")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test"
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_compile_caching(self) -> None:
        cond = RegexCondition("path", r"/test")
        compiled1 = cond.compile()
        compiled2 = cond.compile()
        assert compiled1 is compiled2
    
    def test_serialization(self) -> None:
        cond = RegexCondition("path", r"/admin", negate=True)
        data = cond.to_dict()
        
        assert data["field"] == "path"
        assert data["pattern"] == r"/admin"
        assert data["negate"] is True
        assert data["type"] == "regex"
        
        restored = RegexCondition.from_dict(data)
        assert restored.field == "path"
        assert restored.pattern == r"/admin"
    
    def test_from_rule_condition(self) -> None:
        rc = RuleCondition(
            field="ip",
            condition_type=ConditionType.REGEX,
            pattern=r"192\.168\..*",
            negate=False
        )
        
        cond = RegexCondition.from_rule_condition(rc)
        assert isinstance(cond, RegexCondition)
        assert cond.field == "ip"
        assert cond.pattern == r"192\.168\..*"


class TestBase64RegexCondition:
    """Test Base64RegexCondition."""
    
    def test_decode_and_match(self) -> None:
        # Base64 encode "/admin"
        encoded = base64.b64encode(b"/admin").decode()
        
        cond = Base64RegexCondition("data", r"/admin")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"data": encoded}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
        assert result.metadata["decoded"] == "/admin"
    
    def test_invalid_base64(self) -> None:
        cond = Base64RegexCondition("data", r"/admin")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"data": "not-valid-base64!!!"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_from_rule_condition(self) -> None:
        rc = RuleCondition(
            field="payload",
            condition_type=ConditionType.BASE64_REGEX,
            pattern=r"SELECT.*FROM",
            negate=False
        )
        
        cond = Base64RegexCondition.from_rule_condition(rc)
        assert isinstance(cond, Base64RegexCondition)
        assert cond.pattern == r"SELECT.*FROM"


class TestPlainCondition:
    """Test PlainCondition."""
    
    def test_exact_match(self) -> None:
        cond = PlainCondition("method", "GET")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"method": "GET"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
        assert result.matched_value == "GET"
    
    def test_case_insensitive_match(self) -> None:
        cond = PlainCondition("method", "get", case_sensitive=False)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"method": "GET"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_no_match(self) -> None:
        cond = PlainCondition("method", "POST")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"method": "GET"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_non_string_value(self) -> None:
        cond = PlainCondition("code", "200")
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"code": 200}  # Integer
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_serialization(self) -> None:
        cond = PlainCondition("method", "GET", case_sensitive=True)
        data = cond.to_dict()
        
        assert data["value"] == "GET"
        assert data["case_sensitive"] is True
        
        restored = PlainCondition.from_dict(data)
        assert restored.value == "GET"
        assert restored.case_sensitive is True


class TestLengthCondition:
    """Test LengthCondition."""
    
    def test_length_gte(self) -> None:
        cond = LengthCondition("path", 10, ConditionType.LENGTH_GTE)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/very/long/path"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
        assert result.metadata["actual"] == len("/very/long/path")
    
    def test_length_lt(self) -> None:
        cond = LengthCondition("path", 10, ConditionType.LENGTH_LT)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/short"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_length_eq(self) -> None:
        cond = LengthCondition("path", 6, ConditionType.LENGTH_EQ)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/admin"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_no_match(self) -> None:
        cond = LengthCondition("path", 100, ConditionType.LENGTH_GTE)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/short"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_list_length(self) -> None:
        cond = LengthCondition("items", 3, ConditionType.LENGTH_EQ)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"items": ["a", "b", "c"]}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_invalid_operator(self) -> None:
        with pytest.raises(ValueError, match="Invalid length operator"):
            LengthCondition("path", 10, ConditionType.REGEX)
    
    def test_from_rule_condition(self) -> None:
        rc = RuleCondition(
            field="ua",
            condition_type=ConditionType.LENGTH_GT,
            pattern="",
            length_value=100,
            negate=False
        )
        
        cond = LengthCondition.from_rule_condition(rc)
        assert isinstance(cond, LengthCondition)
        assert cond.length == 100
        assert cond.operator_type == ConditionType.LENGTH_GT


class TestCompoundCondition:
    """Test CompoundCondition."""
    
    def test_and_all_match(self) -> None:
        cond = CompoundCondition([
            RegexCondition("path", r"/admin"),
            RegexCondition("method", r"POST"),
        ], operator="AND")
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/admin/login", "method": "POST"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_and_one_fails(self) -> None:
        cond = CompoundCondition([
            RegexCondition("path", r"/admin"),
            RegexCondition("method", r"GET"),  # Entry has POST
        ], operator="AND")
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/admin/login", "method": "POST"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_or_one_matches(self) -> None:
        cond = CompoundCondition([
            RegexCondition("path", r"/admin"),
            RegexCondition("path", r"/api"),
        ], operator="OR")
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/api/users"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched
    
    def test_or_none_match(self) -> None:
        cond = CompoundCondition([
            RegexCondition("path", r"/admin"),
            RegexCondition("path", r"/api"),
        ], operator="OR")
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/home"}
        )
        
        result = cond.evaluate(entry)
        assert not result.matched
    
    def test_negation(self) -> None:
        cond = CompoundCondition([
            RegexCondition("path", r"/admin"),
        ], operator="AND", negate=True)
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"path": "/home"}
        )
        
        result = cond.evaluate(entry)
        assert result.matched  # Negated: no match becomes match
    
    def test_compile_subconditions(self) -> None:
        sub1 = RegexCondition("path", r"/test")
        sub2 = RegexCondition("method", r"GET")
        cond = CompoundCondition([sub1, sub2])
        
        compiled = cond.compile()
        assert len(compiled) == 2
        assert sub1._compiled is not None
        assert sub2._compiled is not None


class TestConditionEdgeCases:
    """Test edge cases and error handling."""
    
    def test_regex_invalid_pattern(self) -> None:
        # Invalid regex should raise during compile
        with pytest.raises(re.error):
            cond = RegexCondition("path", r"[invalid")
            cond.compile()
    
    def test_base64_with_padding(self) -> None:
        # Test various padding scenarios
        test_strings = [b"/admin", b"/test", b"/longer/path"]
        for s in test_strings:
            encoded = base64.b64encode(s).decode().rstrip("=")  # Remove padding
            cond = Base64RegexCondition("data", s.decode())
            entry = LogEntry(
                timestamp=datetime.utcnow(),
                ip="192.168.1.1",
                raw_line="test",
                parsed_fields={"data": encoded}
            )
            result = cond.evaluate(entry)
            assert result.matched, f"Failed for {s}"
    
    def test_length_with_non_collection(self) -> None:
        # Test with integer (converted to string)
        cond = LengthCondition("code", 3, ConditionType.LENGTH_EQ)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"code": 404}
        )
        
        result = cond.evaluate(entry)
        assert result.matched  # "404" has length 3
