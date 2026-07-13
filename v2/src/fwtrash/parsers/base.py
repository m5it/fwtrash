"""Abstract base class and registry for log parsers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, TypeVar

from fwtrash.core.models import LogEntry

T = TypeVar("T", bound="LogParser")

T = TypeVar("T", bound="LogParser")


class ParseError(Exception):
    """Raised when a log line cannot be parsed."""
    
    def __init__(self, message: str, line: str | None = None, parser_name: str | None = None) -> None:
        super().__init__(message)
        self.line = line
        self.parser_name = parser_name


class LogParser(ABC):
    """Abstract base class for log format parsers.
    
    Parsers are responsible for converting raw log lines into
    structured LogEntry objects that the rule engine can evaluate.
    """
    
    # Registry of parser implementations
    _registry: ClassVar[dict[str, type[LogParser]]] = {}
    
    # Parser metadata - subclasses must define these
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    supported_formats: ClassVar[list[str]] = []
    
    def __init__(self, encoding: str = "utf-8") -> None:
        self.encoding = encoding
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
    
    @abstractmethod
    def parse(self, line: str) -> LogEntry:
        """Parse a single log line into a LogEntry.
        
        Args:
            line: Raw log line from input stream
            
        Returns:
            LogEntry with parsed fields
            
        Raises:
            ParseError: If line cannot be parsed by this parser
        """
        pass
    
    @abstractmethod
    def can_parse(self, line: str) -> float:
        """Check if this parser can handle the given line.
        
        Returns:
            Confidence score 0.0-1.0 indicating how well this
            parser matches the line format
        """
        pass
    
    def _compile_pattern(self, name: str, pattern: str) -> re.Pattern[str]:
        """Compile and cache regex pattern."""
        if name not in self._compiled_patterns:
            self._compiled_patterns[name] = re.compile(pattern)
        return self._compiled_patterns[name]
    
    @classmethod
    def register(cls, parser_class: type[T]) -> type[T]:
        """Register a parser implementation."""
        cls._registry[parser_class.name] = parser_class
        return parser_class
    
    @classmethod
    def get_parser(cls, name: str) -> LogParser:
        """Get parser instance by name."""
        if name not in cls._registry:
            raise ValueError(f"Unknown parser: {name}. Available: {list(cls._registry.keys())}")
        return cls._registry[name]()
    
    @classmethod
    def list_parsers(cls) -> dict[str, str]:
        """List all registered parsers."""
        return {name: pc.description for name, pc in cls._registry.items()}
    
    @classmethod
    def auto_detect(cls, line: str) -> LogParser | None:
        """Auto-detect appropriate parser for a line."""
        best_parser: type[LogParser] | None = None
        best_score = 0.0
        
        for parser_class in cls._registry.values():
            try:
                parser = parser_class()
                score = parser.can_parse(line)
                if score > best_score:
                    best_score = score
                    best_parser = parser_class
            except Exception:
                continue
        
        return best_parser() if best_parser else None
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name})"


# Convenience decorator for registration
def register_parser(parser_class: type[T]) -> type[T]:
    """Decorator to register a parser class."""
    return LogParser.register(parser_class)
