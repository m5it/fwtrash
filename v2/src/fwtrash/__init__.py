"""FWTrash v2.0 - Modern Security Log Analyzer

A complete rewrite of the original FWTrash with:
- Typed Pydantic models
- Plugin-based parser architecture
- Async pipeline processing
- Real-time dashboard (optional)
- Full test coverage
"""

__version__ = "2.0.0"
__author__ = "FWTrash Contributors"

from fwtrash.core.models import LogEntry, Rule, BlockDecision, PipelineState
from fwtrash.engine.pipeline import Pipeline

__all__ = [
    "LogEntry",
    "Rule", 
    "BlockDecision",
    "PipelineState",
    "Pipeline",
]
