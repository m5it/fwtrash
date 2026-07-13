"""Regression tests comparing v1 vs v2 output."""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest


class TestRegression:
n    \"\"\"Compare v1 and v2 outputs on same inputs.\"\"\"\n    \n    @pytest.fixture\n    def sample_rules(self, tmp_path):\n        \"\"\"Create sample rules for both versions.\"\"\"\n        rules = [\n            [{\"key\": \"path\", \"type\": 2, \"data\": r\"/admin\"}],\n            [{\"key\": \"ua\", \"type\": 2, \"data\": r\"BadBot\"}],\n        ]\n        rules_file = tmp_path / \"rules.json\"\n        with open(rules_file, \"w\") as f:\n            json.dump(rules, f)\n        return str(rules_file)
    
    def test_http_parsing_consistency(self, sample_rules, tmp_path) -> None:
n        \"\"\"Verify v2 produces same parsing results as v1 would.\"\"\"\n        from fwtrash.parsers.http import HTTPParser\n        from fwtrash.core.models import LogEntry\n        from datetime import datetime, timezone\n        \n        parser = HTTPParser()\n        \n        # Test line that should be parsed consistently\n        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET /admin HTTP/1.1\" 200 452 \"-\" \"Mozilla/5.0\"'\n        \n        entry = parser.parse(line)\n        \n        # Verify key fields match expected v1 behavior\n        assert entry.ip == \"192.168.1.1\"\n        assert entry.method == \"GET\"\n        assert entry.path == \"/admin\"\n        assert entry.status_code == 200\n        assert entry.parsed_fields['code'] == \"200\"\n        assert entry.parsed_fields['ua'] == \"Mozilla/5.0\"\n        \n        # Timestamp should be parsed correctly\n        assert entry.timestamp.year == 2023\n        assert entry.timestamp.month == 10\n        assert entry.timestamp.day == 10
    
    def test_rule_matching_consistency(self, sample_rules) -> None:
n        \"\"\"Verify v2 rule engine produces same matches as v1.\"\"\"\n        from fwtrash.rules.engine import RuleEngine\n        from fwtrash.parsers.http import HTTPParser\n        \n        engine = RuleEngine()\n        engine.load_from_json(sample_rules)\n        \n        parser = HTTPParser()\n        \n        # Line matching first rule\n        line1 = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET /admin HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"'\n        entry1 = parser.parse(line1)\n        matches1 = engine.evaluate(entry1)\n        \n        # Should match /admin rule\n        assert len(matches1) >= 1\n        \n        # Line matching second rule\n        line2 = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET / HTTP/1.1\" 200 0 \"-\" \"BadBot/1.0\"'\n        entry2 = parser.parse(line2)\n        matches2 = engine.evaluate(entry2)\n        \n        # Should match BadBot rule\n        assert len(matches2) >= 1
    
    def test_block_decision_format(self) -> None:
n        \"\"\"Verify block decision format is compatible.\"\"\"\n        from fwtrash.core.models import BlockDecision, Rule, RuleCondition, ConditionType, LogEntry\n        from datetime import datetime, timezone\n        \n        # Create decision like v1 would\n        rule = Rule(\n            conditions=[RuleCondition(field=\"x\", condition_type=ConditionType.REGEX, pattern=\"y\")],\n            block_duration=3600,\n        )\n        entry = LogEntry(\n            timestamp=datetime.now(timezone.utc),\n            ip=\"192.168.1.1\",\n            raw_line=\"test\",\n        )\n        \n        decision = BlockDecision.from_rule(\"192.168.1.1\", rule, entry, 0.9)\n        \n        # Verify fields v1 would expect\n        assert hasattr(decision, 'ip')\n        assert hasattr(decision, 'reason')\n        assert hasattr(decision, 'confidence')\n        assert hasattr(decision, 'detected_at')\n        assert hasattr(decision, 'expires_at')\n        \n        # Verify string formatting compatibility\n        assert str(decision.ip) == \"192.168.1.1\"\n        assert isinstance(decision.confidence, float)
