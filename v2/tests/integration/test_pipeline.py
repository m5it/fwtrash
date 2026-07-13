"""Integration tests for full pipeline."""

import asyncio
from io import BytesIO

import pytest

from fwtrash.core.blocking import BlockManager, BlockManagerConfig, NullBackend
from fwtrash.core.models import PipelineConfig, PipelineState
from fwtrash.engine.output import FileOutputHandler
from fwtrash.engine.pipeline import Pipeline
from fwtrash.parsers.http import HTTPParser
from fwtrash.rules.engine import RuleEngine


class TestPipelineIntegration:
    """Integration tests with real components."""
    
    @pytest.fixture
    def sample_rules_file(self, tmp_path):
        """Create temporary rules file."""
        rules = [
n            [{"key": "path", "type": 2, "data": r"/admin"}],\n            [{"key": "ua", "type": 2, "data": r"BadBot"}],\n        ]\n        import json\n        rules_file = tmp_path / "test.rules"\n        with open(rules_file, "w") as f:\n            json.dump(rules, f)\n        return str(rules_file)
    
    @pytest.mark.asyncio
    async def test_full_pipeline(self, sample_rules_file, tmp_path) -> None:
n        \"\"\"Test complete pipeline flow.\"\"\"\n        config = PipelineConfig(\n            rules_file=sample_rules_file,\n            badips_file=str(tmp_path / "badips.txt"),
n            trash_file=str(tmp_path / "trash.txt"),
n        )
n        \n        parser = HTTPParser()\n        rule_engine = RuleEngine()\n        rule_engine.load_from_json(config.rules_file)
n        \n        state = PipelineState(config=config)
n        output_handler = FileOutputHandler(\n            trash_file=config.trash_file,\n            badips_file=config.badips_file,
n        )
n        \n        pipeline = Pipeline(\n            config=config,\n            parser=parser,\n            rule_engine=rule_engine,\n            state=state,\n            output_handler=output_handler,\n            blocking_backend=NullBackend(),
n        )
n        \n        # Process lines\n        lines = [\n            '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET / HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0\"',\n            '192.168.1.1 - - [10/Oct/2023:13:55:37 -0400] \"GET /admin HTTP/1.1\" 200 452 \"-\" \"Mozilla/5.0\"',\n            '10.0.0.1 - - [10/Oct/2023:13:55:38 -0400] \"GET / HTTP/1.1\" 200 0 \"-\" \"BadBot/1.0\"',\n        ]
n        \n        for line in lines:\n            await pipeline.process_line(line)
n        \n        # Verify results\n        assert state.stats.total_processed == 3\n        assert state.stats.total_trash == 2  # /admin and BadBot\n        assert state.stats.total_allowed == 1  # Clean request
n        \n        # Cleanup\n        await output_handler.close()
    
    @pytest.mark.asyncio
    async def test_allowlist(self, sample_rules_file, tmp_path) -> None:
n        \"\"\"Test that allowlisted IPs are not blocked.\"\"\"\n        config = PipelineConfig(rules_file=sample_rules_file)\n        \n        parser = HTTPParser()\n        rule_engine = RuleEngine()\n        rule_engine.load_from_json(config.rules_file)
n        \n        state = PipelineState(config=config)\n        state.allowed_ips = {"192.168.1.1"}  # Allow this IP
n        \n        pipeline = Pipeline(\n            config=config,\n            parser=parser,\n            rule_engine=rule_engine,\n            state=state,\n        )
n        \n        # This would normally trigger a block, but IP is allowed\n        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET /admin HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"'\n        await pipeline.process_line(line)
n        \n        assert state.stats.total_allowed == 1\n        assert state.stats.total_trash == 0  # Not counted as trash because allowed
    
    @pytest.mark.asyncio
    async def test_concurrent_processing(self, sample_rules_file) -> None:
n        \"\"\"Test concurrent line processing.\"\"\"\n        config = PipelineConfig(rules_file=sample_rules_file)
n        \n        parser = HTTPParser()\n        rule_engine = RuleEngine()\n        rule_engine.load_from_json(config.rules_file)
n        \n        state = PipelineState(config=config)
n        pipeline = Pipeline(config=config, parser=parser, rule_engine=rule_engine, state=state)
n        \n        # Process many lines concurrently\n        lines = [\n            f'192.168.1.{i} - - [10/Oct/2023:13:55:{i:02d} -0400] \"GET /admin HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"'\n            for i in range(100)\n        ]
n        \n        await asyncio.gather(*[pipeline.process_line(line) for line in lines])
n        \n        assert state.stats.total_processed == 100
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, sample_rules_file) -> None:
n        \"\"\"Test rate limiting doesn't break processing.\"\"\"\n        config = PipelineConfig(rules_file=sample_rules_file)
n        \n        parser = HTTPParser()\n        rule_engine = RuleEngine()\n        rule_engine.load_from_json(config.rules_file)
n        \n        state = PipelineState(config=config)\n        pipeline = Pipeline(config=config, parser=parser, rule_engine=rule_engine, state=state)
n        \n        # Process lines rapidly\n        for i in range(50):\n            line = f'192.168.1.1 - - [10/Oct/2023:13:55:{i%60:02d} -0400] \"GET / HTTP/1.1\" 200 0 \"-\" \"Mozilla/5.0\"'\n            await pipeline.process_line(line)
n        \n        assert state.stats.total_processed == 50
