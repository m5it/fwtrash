"""Unit tests for BlockManager."""

import asyncio
from datetime import datetime, timedelta

import pytest

from fwtrash.core.blocking import (
    BlockManager,
    BlockManagerConfig,
    FileBackend,
    IptablesBackend,
    NullBackend,
)
from fwtrash.core.models import BlockDecision, PipelineState


class TestNullBackend:
    """Test NullBackend."""
    
    @pytest.mark.asyncio
    async def test_block_noop(self) -> None:
        backend = NullBackend()
        decision = BlockDecision(
            ip="192.168.1.1",
            reason="test",
            rule_id="r1",
            confidence=0.9,
        )
        result = await backend.block(decision)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_unblock_noop(self) -> None:
        backend = NullBackend()
        result = await backend.unblock("192.168.1.1")
        assert result is True
    
    @pytest.mark.asyncio
    async def test_is_blocked_always_false(self) -> None:
        backend = NullBackend()
        result = await backend.is_blocked("192.168.1.1")
        assert result is False


class TestBlockManager:
    """Test BlockManager."""
    
    @pytest.fixture
    def manager(self) -> BlockManager:
        state = PipelineState()
        return BlockManager(
            state=state,
            backend=NullBackend(),
            config=BlockManagerConfig(enable_auto_unblock=False)
        )
    
    def test_calculate_duration(self, manager: BlockManager) -> None:
        high = manager._calculate_duration(0.9)
        med = manager._calculate_duration(0.6)
        low = manager._calculate_duration(0.3)
        
        assert high == manager.config.high_confidence_duration
        assert med == manager.config.medium_confidence_duration
        assert low == manager.config.low_confidence_duration
    
    def test_is_private_ip(self, manager: BlockManager) -> None:
        assert manager._is_private_ip("192.168.1.1") is True
        assert manager._is_private_ip("10.0.0.1") is True
        assert manager._is_private_ip("172.16.0.1") is True
        assert manager._is_private_ip("8.8.8.8") is False
    
    def test_is_allowed(self, manager: BlockManager) -> None:
        manager.state.allowed_ips = {"192.168.1.1"}
        assert manager._is_allowed("192.168.1.1") is True
        assert manager._is_allowed("8.8.8.8") is False
    
    @pytest.mark.asyncio
    async def test_should_block_low_confidence(self, manager: BlockManager) -> None:
        decision = BlockDecision(
            ip="8.8.8.8",
            reason="test",
            rule_id="r1",
            confidence=0.3,  # Below threshold
        )
        result = await manager.should_block(decision)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_should_block_allowed_ip(self, manager: BlockManager) -> None:
        manager.state.allowed_ips = {"192.168.1.1"}
        decision = BlockDecision(
            ip="192.168.1.1",
            reason="test",
            rule_id="r1",
            confidence=0.9,
        )
        result = await manager.should_block(decision)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_execute_block(self, manager: BlockManager) -> None:
        decision = BlockDecision(
            ip="8.8.8.8",
            reason="test",
            rule_id="r1",
            confidence=0.9,
        )
        result = await manager.execute_block(decision)
        assert result is True
        assert decision.executed is True
        assert "8.8.8.8" in manager.state.active_blocks
    
    @pytest.mark.asyncio
    async def test_unblock(self, manager: BlockManager) -> None:
        decision = BlockDecision(
            ip="8.8.8.8",
            reason="test",
            rule_id="r1",
            confidence=0.9,
        )
        await manager.execute_block(decision)
        assert "8.8.8.8" in manager.state.active_blocks
        
        await manager.unblock("8.8.8.8")
        assert "8.8.8.8" not in manager.state.active_blocks
    
    @pytest.mark.asyncio
    async def test_cleanup_expired(self, manager: BlockManager) -> None:
        # Add expired block
        expired = BlockDecision(
            ip="1.2.3.4",
            reason="test",
            rule_id="r1",
            confidence=0.9,
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        expired.mark_executed()
        manager.state.active_blocks["1.2.3.4"] = expired
        
        # Add active block
        active = BlockDecision(
            ip="5.6.7.8",
            reason="test",
            rule_id="r2",
            confidence=0.9,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        active.mark_executed()
        manager.state.active_blocks["5.6.7.8"] = active
        
        count = await manager.cleanup_expired()
        assert count == 1
        assert "1.2.3.4" not in manager.state.active_blocks
        assert "5.6.7.8" in manager.state.active_blocks
    
    def test_get_stats(self, manager: BlockManager) -> None:
        stats = manager.get_stats()
        assert "total_blocks" in stats
        assert "backend_type" in stats
