"""Core Pydantic models for FWTrash v2.0.

These typed models replace the dict-based global state from v0.6,
providing validation, serialization, and IDE support.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Literal

from pydantic import BaseModel, Field, field_serializer, field_validator


class LogLevel(str, Enum):
    """Severity levels for log entries and events."""
    
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class BlockAction(str, Enum):
    """Actions that can be taken when a threat is detected."""
    
    DROP = "drop"           # Block immediately
    LOG = "log"             # Log only, no block
    RATE_LIMIT = "ratelimit"  # Rate limit the IP
    ALERT = "alert"         # Send alert notification


class ConditionType(str, Enum):
    """Types of rule conditions matching v0.6 behavior."""
    
    REGEX = "regex"                    # Type 2: plain regex
    BASE64_REGEX = "base64_regex"      # Type 1: base64 decode then regex
    PLAIN = "plain"                    # Type 3: exact string match
    LENGTH_GTE = "length_gte"          # Type 4: length >=
    LENGTH_GT = "length_gt"            # Type 5: length >
    LENGTH_LTE = "length_lte"          # Type 6: length <=
    LENGTH_LT = "length_lt"            # Type 7: length <
    LENGTH_EQ = "length_eq"            # Type 8: length ==


class ParserConfig(BaseModel):
    """Configuration for log parsers."""
    
    name: str = Field(..., description="Parser identifier")
    timestamp_format: str = Field(
        default="%d/%b/%Y:%H:%M:%S %z",
        description="strftime format for parsing timestamps"
    )
    field_patterns: dict[str, str] = Field(
        default_factory=dict,
        description="Regex patterns for extracting fields"
    )
    encoding: str = Field(default="utf-8", description="Log file encoding")
    
    class Config:
        frozen = True


class LogEntry(BaseModel):
    """A single parsed log entry.
    
    Replaces the dict-based log entries from v0.6 with full typing.
    """
    
    # Core fields
    timestamp: datetime = Field(..., description="When the request occurred")
    ip: str = Field(..., description="Source IP address")
    raw_line: str = Field(..., description="Original unparsed log line")
    
    # Parsed fields from specific log formats
    parsed_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Format-specific extracted fields (req, code, ua, etc.)"
    )
    
    # Tracking fields
    entry_id: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:8],
        description="Unique identifier for this entry"
    )
    parsed_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this entry was parsed"
    )
    
    # Optional HTTP-specific fields (common case)
    method: str | None = Field(default=None, description="HTTP method")
    path: str | None = Field(default=None, description="Request path")
    status_code: int | None = Field(default=None, description="HTTP status code")
    user_agent: str | None = Field(default=None, description="User agent string")
    referer: str | None = Field(default=None, description="HTTP referer")
    response_size: int | None = Field(default=None, description="Response size in bytes")
    
    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP validation."""
        if not v or v == "-":
            return "0.0.0.0"
        return v
    
    @property
    def hash(self) -> str:
        """Generate hash for deduplication (replaces v0.6 crc32b)."""
        content = f"{self.ip}:{self.timestamp.isoformat()}:{self.raw_line}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def get_field(self, key: str, default: Any = None) -> Any:
        """Safely get a parsed field."""
        return self.parsed_fields.get(key, default)
    
    class Config:
        frozen = False  # Allow mutation for state tracking


class RuleCondition(BaseModel):
    """A single condition within a rule.
    
    Maps to v0.6 rule objects with key, type, data fields.
    """
    
    field: str = Field(..., description="Field to check (ip, req, ua, etc.)")
    condition_type: ConditionType = Field(..., description="Type of comparison")
    pattern: str = Field(..., description="Pattern to match against")
    negate: bool = Field(default=False, description="Invert the match")
    
    # For length-based conditions
    length_value: int | None = Field(default=None, description="For length comparisons")
    
    # Brute force protection
    bruteforce_key: int | None = Field(
        default=None,
        ge=0,
        le=999,
        description="Brute force tracking key (0-999)"
    )
    
    def __str__(self) -> str:
        return f"{self.field}:{self.condition_type}:{self.pattern[:30]}"
    
    class Config:
        frozen = True


class RuleMetadata(BaseModel):
    """Metadata for a rule."""
    
    name: str = Field(default="", description="Human-readable rule name")
    description: str = Field(default="", description="What this rule detects")
    severity: LogLevel = Field(default=LogLevel.WARNING)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime | None = None
    
    class Config:
        frozen = False


class Rule(BaseModel):
    """A detection rule with conditions and actions.
    
    Replaces the JSON rule arrays from v0.6 with typed structure.
    """
    
    rule_id: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:12],
        description="Unique rule identifier"
    )
    conditions: list[RuleCondition] = Field(
        ...,
        min_length=1,
        description="Conditions that must all match"
    )
    action: BlockAction = Field(default=BlockAction.LOG)
    metadata: RuleMetadata = Field(default_factory=RuleMetadata)
    
    # Action configuration
    block_duration: int = Field(
        default=3600,
        description="Seconds to block IP (0 = permanent)"
    )
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score required to trigger"
    )
    
    # Rate limiting
    rate_limit_count: int | None = Field(
        default=None,
        description="Trigger after N matches within time window"
    )
    rate_limit_window: int | None = Field(
        default=None,
        description="Time window in seconds for rate limiting"
    )
    
    def matches_confidence(self, score: float) -> bool:
        """Check if confidence score meets threshold."""
        return score >= self.confidence_threshold
    
    @property
    def is_brute_force_rule(self) -> bool:
        """Check if this rule uses brute force tracking."""
        return any(c.bruteforce_key is not None for c in self.conditions)
    
    class Config:
        frozen = False


class BlockDecision(BaseModel):
    """A decision to block an IP.
    
    Replaces the g_badips array with full context.
    """
    
    ip: str = Field(..., description="IP address to block")
    reason: str = Field(..., description="Why this IP was blocked")
    rule_id: str = Field(..., description="Rule that triggered the block")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0-1)"
    )
    
    # Timing
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(
        default=None,
        description="When block should be removed (None = permanent)"
    )
    
    # Context
    log_entry: LogEntry | None = Field(
        default=None,
        description="The log entry that triggered this"
    )
    matched_conditions: list[str] = Field(
        default_factory=list,
        description="Which conditions matched"
    )
    
    # State
    executed: bool = Field(default=False, description="Was iptables command run?")
    executed_at: datetime | None = None
    unblocked_at: datetime | None = None
    
    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, v: datetime | None, info: Any) -> datetime | None:
        """Ensure expiration is in the future."""
        if v is not None and v <= datetime.utcnow():
            raise ValueError("Expiration must be in the future")
        return v
    
    @property
    def is_expired(self) -> bool:
        """Check if this block has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if block is currently active."""
        return self.executed and not self.is_expired and self.unblocked_at is None
    
    def mark_executed(self) -> None:
        """Mark this block as executed."""
        self.executed = True
        self.executed_at = datetime.utcnow()
    
    def mark_unblocked(self) -> None:
        """Mark this block as removed."""
        self.unblocked_at = datetime.utcnow()
    
    @classmethod
    def from_rule(
        cls,
        ip: str,
        rule: Rule,
        log_entry: LogEntry,
        confidence: float = 1.0
    ) -> BlockDecision:
        """Create a BlockDecision from a matched Rule."""
        expires = None
        if rule.block_duration > 0:
            expires = datetime.utcnow() + timedelta(seconds=rule.block_duration)
        
        return cls(
            ip=ip,
            reason=rule.metadata.description or rule.metadata.name,
            rule_id=rule.rule_id,
            confidence=confidence,
            log_entry=log_entry,
            expires_at=expires
        )
    
    class Config:
        frozen = False


class PipelineStats(BaseModel):
    """Runtime statistics for the pipeline.
    
    Replaces the global Stats dict from v0.6.
    """
    
    # Counters
    total_processed: int = Field(default=0, description="Total log lines processed")
    total_allowed: int = Field(default=0, description="Clean entries passed")
    total_blocked: int = Field(default=0, description="Entries that triggered blocks")
    total_trash: int = Field(default=0, description="Entries flagged as trash")
    total_errors: int = Field(default=0, description="Parse/processing errors")
    
    # Rate tracking
    start_time: datetime = Field(default_factory=datetime.utcnow)
    last_entry_at: datetime | None = None
    
    # Recent tracking (for display)
    recent_trash: list[LogEntry] = Field(
        default_factory=list,
        description="Last N trash entries for stats display"
    )
    recent_pure: list[LogEntry] = Field(
        default_factory=list,
        description="Last N clean entries for stats display"
    )
    
    # Brute force tracking
    brute_force_hits: dict[int, int] = Field(
        default_factory=dict,
        description="Counter per bruteforce_key"
    )
    
    @property
    def uptime_seconds(self) -> float:
        """Seconds since pipeline started."""
        return (datetime.utcnow() - self.start_time).total_seconds()
    
    @property
    def entries_per_second(self) -> float:
        """Processing rate."""
        uptime = self.uptime_seconds
        if uptime <= 0:
            return 0.0
        return self.total_processed / uptime
    
    def increment(self, counter: Literal["processed", "allowed", "blocked", "trash", "errors"]) -> None:
        """Increment a counter."""
        match counter:
            case "processed":
                self.total_processed += 1
            case "allowed":
                self.total_allowed += 1
            case "blocked":
                self.total_blocked += 1
            case "trash":
                self.total_trash += 1
            case "errors":
                self.total_errors += 1
    
    def add_recent_trash(self, entry: LogEntry, max_items: int = 100) -> None:
        """Add entry to recent trash list."""
        self.recent_trash.append(entry)
        if len(self.recent_trash) > max_items:
            self.recent_trash.pop(0)
    
    def add_recent_pure(self, entry: LogEntry, max_items: int = 100) -> None:
        """Add entry to recent clean list."""
        self.recent_pure.append(entry)
        if len(self.recent_pure) > max_items:
            self.recent_pure.pop(0)
    
    class Config:
        frozen = False


class PipelineConfig(BaseModel):
    """Configuration for the processing pipeline."""
    
    # Input/Output
    parser: ParserConfig = Field(default_factory=lambda: ParserConfig(name="auto"))
    
    # Files
    rules_file: str | None = None
    badips_file: str | None = None
    trash_file: str | None = None
    allowed_ips_file: str | None = None
    
    # Behavior
    verbose: bool = True
    disable_stats: bool = False
    stop_on_new_day: bool = False
    
    # Display
    stat_display_keys: list[str] = Field(default_factory=list)
    stat_display_template: str = ""
    max_pure_memory: int = 100  # g_opt_pure_max from v0.6
    
    # Auto-save
    autosave_interval: int = 10  # Save options every N entries
    
    # Commands
    on_badip_command: str | None = None  # -c command template
    
    class Config:
        frozen = False


class PipelineState(BaseModel):
    """Complete state of a running pipeline.
    
    Replaces all global state variables from v0.6.
    """
    
    # Identity
    pipeline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Configuration
    config: PipelineConfig = Field(default_factory=PipelineConfig)
    
    # Runtime state
    stats: PipelineStats = Field(default_factory=PipelineStats)
    active_blocks: dict[str, BlockDecision] = Field(
        default_factory=dict,
        description="Currently active blocks by IP"
    )
    allowed_ips: set[str] = Field(
        default_factory=set,
        description="Never-block IPs"
    )
    loaded_rules: list[Rule] = Field(default_factory=list)
    
    # Persistence
    last_checkpoint: datetime | None = None
    checkpoint_data: dict[str, Any] = Field(default_factory=dict)
    
    # Status
    is_running: bool = False
    is_paused: bool = False
    shutdown_requested: bool = False
    
    def get_block_for_ip(self, ip: str) -> BlockDecision | None:
        """Get active block for IP if exists."""
        return self.active_blocks.get(ip)
    
    def add_block(self, decision: BlockDecision) -> None:
        """Add a new block decision."""
        self.active_blocks[decision.ip] = decision
        self.stats.increment("blocked")
    
    def remove_block(self, ip: str) -> BlockDecision | None:
        """Remove and return a block."""
        return self.active_blocks.pop(ip, None)
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is in allowlist."""
        return ip in self.allowed_ips
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP currently has active block."""
        decision = self.active_blocks.get(ip)
        return decision is not None and decision.is_active
    
    def checkpoint(self) -> None:
        """Save current state for recovery."""
        self.last_checkpoint = datetime.utcnow()
        self.checkpoint_data = {
            "processed": self.stats.total_processed,
            "blocks": len(self.active_blocks),
            "rules": len(self.loaded_rules)
        }
    
    @property
    def summary(self) -> dict[str, Any]:
        """Quick status summary."""
        return {
            "pipeline_id": self.pipeline_id,
            "uptime_seconds": self.stats.uptime_seconds,
            "processed": self.stats.total_processed,
            "blocked": self.stats.total_blocked,
            "active_blocks": len(self.active_blocks),
            "rate": round(self.stats.entries_per_second, 2),
            "running": self.is_running
        }
    
    class Config:
        frozen = False
