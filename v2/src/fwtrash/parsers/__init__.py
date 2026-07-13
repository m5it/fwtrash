"""Log parser plugins for different log formats."""

from fwtrash.parsers.base import LogParser, ParseError, register_parser
from fwtrash.parsers.http import HTTPParser
from fwtrash.parsers.ssh import SSHParser

__all__ = ["LogParser", "ParseError", "register_parser", "HTTPParser", "SSHParser"]
__all__ = ["LogParser", "ParseResult", "HTTPParser", "SSHParser"]
