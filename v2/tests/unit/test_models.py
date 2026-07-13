"""Unit tests for core models."""

from datetime import datetime, timedelta, timezone

import pytest

from fwtrash.core.models import (
    BlockAction,
    BlockDecision,
    ConditionType,
    LogEntry,
    LogLevel,
    PipelineConfig,
    PipelineState,
    PipelineStats,
    Rule,
    RuleCondition,
    RuleMetadata,
)


class TestLogEntry:
    """Test LogEntry model."""
    
    def test_basic_creation(self) -> None:
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="192.168.1.1",
            raw_line="test line",
        )
        assert entry.ip == "192.168.1.1"
        assert entry.raw_line == "test line"
    
    def test_hash_generation(self) -> None:
        entry = LogEntry(
            timestamp=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            ip="192.168.1.1",
            raw_line="test",
        )
        hash1 = entry.hash
        hash2 = entry.hash
        assert hash1 == hash2
        assert len(hash1) == 16
    
    def test_get_field(self) -> None:
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="192.168.1.1",
            raw_line="test",
            parsed_fields={"custom": "value"},
        )
        assert entry.get_field("custom") == "value"
        assert entry.get_field("missing") is None
        assert entry.get_field("missing", "default") == "default"
    
    def test_ip_validation(self) -> None:
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="-",
            raw_line="test",
        )
        assert entry.ip == "0.0.0.0"


class TestRule:
    """Test Rule model."""
    
    def test_basic_rule(self) -> None:
        condition = RuleCondition(
            field="path",
            condition_type=ConditionType.REGEX,
            pattern=r"/admin",
        )
        rule = Rule(conditions=[condition])
        assert len(rule.conditions) == 1
    
    def test_confidence_threshold(self) -> None:
        rule = Rule(
            conditions=[RuleCondition(field="x", condition_type=ConditionType.REGEX, pattern="y")],
            confidence_threshold=0.8,
        )
        assert rule.matches_confidence(0.9) is True
        assert rule.matches_confidence(0.7) is False
    
    def test_is_brute_force_rule(self) -> None:
        rule_normal = Rule(conditions=[
            RuleCondition(field="x", condition_type=ConditionType.REGEX, pattern="y")
        ])
        rule_brute = Rule(conditions=[
            RuleCondition(
                field="x",
                condition_type=ConditionType.REGEX,
                pattern="y",
                bruteforce_key=1,
            )
        ])
        assert rule_normal.is_brute_force_rule is False
        assert rule_brute.is_brute_force_rule is True


class TestBlockDecision:
    """Test BlockDecision model."""
    
    def test_creation(self) -> None:
        decision = BlockDecision(
            ip="192.168.1.1",
            reason="Test block",
            rule_id="rule-123",
            confidence=0.9,
        )
        assert decision.ip == "192.168.1.1"
        assert decision.confidence == 0.9
    
    def test_expiration(self) -> None:
        past = datetime.utcnow() - timedelta(hours=1)
        future = datetime.utcnow() + timedelta(hours=1)
        
        expired = BlockDecision(
            ip="1.2.3.4",
            reason="test",
            rule_id="r1",
            confidence=0.5,
            expires_at=past,
        )
        active = BlockDecision(
            ip="5.6.7.8",
            reason="test",
            rule_id="r2",
            confidence=0.5,
            expires_at=future,
        )
        
        assert expired.is_expired is True
        assert active.is_expired is False
        assert active.is_active is False
        
        active.mark_executed()
        assert active.is_active is True
    
    def test_from_rule(self) -> None:
        rule = Rule(
            conditions=[RuleCondition(field="x", condition_type=ConditionType.REGEX, pattern="y")],
            block_duration=3600,
            metadata=RuleMetadata(name="Test Rule", description="Test desc"),
        )
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="192.168.1.1",
            raw_line="test",
        )
        
        decision = BlockDecision.from_rule("192.168.1.1", rule, entry, 0.9)
        
        assert decision.ip == "192.168.1.1"
        assert decision.reason == "Test desc"
        assert decision.rule_id == rule.rule_id
        assert decision.confidence == 0.9
        assert decision.expires_at is not None


class TestPipelineState:
    """Test PipelineState model."""
    
    def test_block_management(self) -> None:
        state = PipelineState()
        
        decision = BlockDecision(
            ip="192.168.1.1",
            reason="test",
            rule_id="r1",
            confidence=0.9,
        )
        
        state.add_block(decision)
        assert state.is_ip_blocked("192.168.1.1") is True
        assert state.get_block_for_ip("192.168.1.1") == decision
        
        removed = state.remove_block("192.168.1.1")
        assert removed == decision
        assert state.is_ip_blocked("192.168.1.1") is False
    
    def test_allowlist(self) -> None:
        state = PipelineState()
        state.allowed_ips = {"192.168.1.1", "10.0.0.1"}
        
        assert state.is_ip_allowed("192.168.1.1") is True
        assert state.is_ip_allowed("8.8.8.8") is False
    
    def test_summary(self) -> None:
        state = PipelineState()
        state.stats.total_processed = 1000
        state.stats.total_blocked = 10
        
        summary = state.summary
        assert summary["processed"] == 1000
        assert summary["blocked"] == 10


class TestPipelineStats:
    """Test PipelineStats model."""
    
    def test_increment(self) -> None:
        stats = PipelineStats()
        
        stats.increment("processed")
        stats.increment("blocked")
        stats.increment("blocked")
        
        assert stats.total_processed == 1
        assert stats.total_blocked == 2
    
    def test_rate_calculation(self) -> None:
        stats = PipelineStats()
        stats.total_processed = 100
        
        assert stats.entries_per_second >= 0
    
    def test_recent_lists(self) -> None:
        stats = PipelineStats()
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="1.2.3.4",
            raw_line="test",
        )
        
        stats.add_recent_trash(entry)
        assert len(stats.recent_trash) == 1
        
        stats.add_recent_pure(entry)
        assert len(stats.recent_pure) == 1


class TestEnums:
    """Test enum values."""
    
    def test_log_level(self) -> None:
        assert LogLevel.DEBUG == "debug"
        assert LogLevel.CRITICAL == "critical"
    
    def test_block_action(self) -> None:
        assert BlockAction.DROP == "drop"
        assert BlockAction.LOG == "log"
    
    def test_condition_type(self) -> None:
        assert ConditionType.REGEX == "regex"
        assert ConditionType.LENGTH_GTE == "length_gte"
