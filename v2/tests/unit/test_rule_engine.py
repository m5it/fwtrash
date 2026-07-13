"""Unit tests for RuleEngine."""

import json
import tempfile
from datetime import datetime

import pytest

from fwtrash.core.models import (
    BlockAction,
    ConditionType,
    LogEntry,
    Rule,
    RuleCondition,
    RuleMetadata,
)
from fwtrash.rules.engine import (
    CompoundCondition,
    RegexCondition,
    RuleEngine,
)


class TestRuleEngine:
    """Test RuleEngine functionality."""
    
    @pytest.fixture
    def engine(self) -> RuleEngine:
        return RuleEngine()
    
    @pytest.fixture
    def sample_entry(self) -> LogEntry:
        return LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.100",
            raw_line='192.168.1.100 - - [10/Oct/2023:13:55:36 -0400] "GET /admin HTTP/1.1" 200 452',
            parsed_fields={
                "method": "GET",
                "path": "/admin",
                "code": "200",
                "ua": "Mozilla/5.0"
            }
        )
    
    def test_empty_engine(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Engine with no rules returns no matches."""
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 0
    
    def test_single_rule_match(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Simple rule matching."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/admin"
                )
            ],
            metadata=RuleMetadata(name="Admin Access")
        )
        
        engine.load_rules([rule])
        matches = engine.evaluate(sample_entry)
        
        assert len(matches) == 1
        assert matches[0][0].metadata.name == "Admin Access"
        assert matches[0][1] == 1.0  # Full confidence
    
    def test_multiple_conditions_and(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Rule with multiple conditions (AND logic)."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/admin"
                ),
                RuleCondition(
                    field="method",
                    condition_type=ConditionType.REGEX,
                    pattern=r"GET"
                )
            ],
            metadata=RuleMetadata(name="Admin GET")
        )
        
        engine.load_rules([rule])
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 1
    
    def test_multiple_conditions_one_fails(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Rule fails if any condition fails."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/admin"
                ),
                RuleCondition(
                    field="method",
                    condition_type=ConditionType.REGEX,
                    pattern=r"POST"  # Entry has GET
                )
            ],
            metadata=RuleMetadata(name="Admin POST")
        )
        
        engine.load_rules([rule])
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 0
    
    def test_disabled_rule(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Disabled rules are skipped."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/admin"
                )
            ],
            metadata=RuleMetadata(enabled=False)
        )
        
        engine.load_rules([rule])
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 0
    
    def test_confidence_threshold(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Rules with confidence threshold."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/admin"
                )
            ],
            confidence_threshold=0.9,
            metadata=RuleMetadata(name="High Confidence")
        )
        
        engine.load_rules([rule])
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 1  # Full confidence 1.0 > 0.9
    
    def test_multiple_rules(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Multiple rules can match same entry."""
        rules = [
            Rule(
                conditions=[RuleCondition(field="path", condition_type=ConditionType.REGEX, pattern=r"/admin")],
                metadata=RuleMetadata(name="Admin Rule")
            ),
            Rule(
                conditions=[RuleCondition(field="method", condition_type=ConditionType.REGEX, pattern=r"GET")],
                metadata=RuleMetadata(name="GET Rule")
            ),
            Rule(
                conditions=[RuleCondition(field="path", condition_type=ConditionType.REGEX, pattern=r"/api")],
                metadata=RuleMetadata(name="API Rule")  # Won't match
            )
        ]
        
        engine.load_rules(rules)
        matches = engine.evaluate(sample_entry)
        
        assert len(matches) == 2
        names = {m[0].metadata.name for m in matches}
        assert "Admin Rule" in names
        assert "GET Rule" in names
        assert "API Rule" not in names
    
    def test_condition_caching(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Same condition reused across rules is cached."""
        rc = RuleCondition(
            field="path",
            condition_type=ConditionType.REGEX,
            pattern=r"/admin"
        )
        
        rules = [
            Rule(conditions=[rc], metadata=RuleMetadata(name=f"Rule {i}"))
            for i in range(5)
        ]
        
        engine.load_rules(rules)
        
        # Should have only 1 cached condition
        assert len(engine._condition_cache) == 1
        
        # But 5 entries in compiled_conditions (one per rule)
        assert len(engine._compiled_conditions) == 5
    
    def test_get_stats(self, engine: RuleEngine) -> None:
        """Engine statistics."""
        rules = [
            Rule(
                conditions=[RuleCondition(field="path", condition_type=ConditionType.REGEX, pattern=r"/test")],
                metadata=RuleMetadata(name="Test")
            )
            for _ in range(10)
        ]
        
        engine.load_rules(rules)
        stats = engine.get_stats()
        
        assert stats["rules_loaded"] == 10
        assert stats["conditions_cached"] == 1  # All same pattern
    
    def test_load_from_json_v06_format(self, engine: RuleEngine, sample_entry: LogEntry) -> None:
        """Load v0.6 JSON format."""
        # v0.6 format: list of lists of condition dicts
        json_data = [
            [
                {"key": "path", "type": 2, "data": r"/admin"},
                {"key": "method", "type": 2, "data": r"GET"}
            ],
            [
                {"key": "ua", "type": 2, "data": r"Bot"}
            ]
        ]
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(json_data, f)
            f.flush()
            
            engine.load_from_json(f.name)
        
        assert len(engine._rules) == 2
        
        # First rule should have 2 conditions
        assert len(engine._rules[0].conditions) == 2
        
        # Test evaluation
        matches = engine.evaluate(sample_entry)
        assert len(matches) == 1  # First rule matches


class TestRuleEngineEdgeCases:
    """Edge case tests."""
    
    def test_empty_conditions(self) -> None:
        """Rule with no conditions should not be allowed."""
        with pytest.raises(ValueError):
            Rule(conditions=[], metadata=RuleMetadata(name="Empty"))
    
    def test_missing_field(self, engine: RuleEngine) -> None:
        """Entry without required field."""
        rule = Rule(
            conditions=[RuleCondition(field="nonexistent", condition_type=ConditionType.REGEX, pattern=r".*")],
            metadata=RuleMetadata(name="Missing Field")
        )
        
        engine.load_rules([rule])
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={}
        )
        
        matches = engine.evaluate(entry)
        assert len(matches) == 0
    
    def test_complex_rule(self, engine: RuleEngine) -> None:
        """Complex rule with multiple condition types."""
        rule = Rule(
            conditions=[
                RuleCondition(field="path", condition_type=ConditionType.REGEX, pattern=r"/admin"),
                RuleCondition(field="path", condition_type=ConditionType.LENGTH_GT, length_value=5),
                RuleCondition(field="method", condition_type=ConditionType.PLAIN, pattern="GET"),
            ],
            metadata=RuleMetadata(name="Complex")
        )
        
        engine.load_rules([rule])
        
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={
                "path": "/admin/dashboard",
                "method": "GET"
            }
        )
        
        matches = engine.evaluate(entry)
        assert len(matches) == 1
    
    def test_bruteforce_rule_detection(self, engine: RuleEngine) -> None:
        """Detect brute force rules."""
        rule = Rule(
            conditions=[
                RuleCondition(
                    field="path",
                    condition_type=ConditionType.REGEX,
                    pattern=r"/login",
                    bruteforce_key=1
                )
            ],
            metadata=RuleMetadata(name="Brute Force")
        )
        
        assert rule.is_brute_force_rule is True
    
    def test_non_bruteforce_rule(self, engine: RuleEngine) -> None:
        """Non-brute force rule."""
        rule = Rule(
            conditions=[
                RuleCondition(field="path", condition_type=ConditionType.REGEX, pattern=r"/admin")
            ],
            metadata=RuleMetadata(name="Normal")
        )
        
        assert rule.is_brute_force_rule is False
