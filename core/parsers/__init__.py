"""
core/parsers/__init__.py

Central registry of built-in format parsers, keyed by the same string used
in Source Pack manifests' `format.type`. Source Packs never instantiate
parsers directly — they reference a format name and the engine resolves it
here, which keeps parser implementations swappable/upgradable without
touching any pack.
"""

from __future__ import annotations

from typing import Dict, Type

from core.parsers.base import BaseFormatParser
from core.parsers.cef_parser import CEFFormatParser
from core.parsers.csv_parser import CSVFormatParser
from core.parsers.fallback import FallbackParser
from core.parsers.json_parser import JSONFormatParser
from core.parsers.kv_parser import KeyValueParser
from core.parsers.regex_parser import RegexFormatParser
from core.parsers.syslog import SyslogParser

BUILTIN_PARSERS: Dict[str, Type[BaseFormatParser]] = {
    "syslog": SyslogParser,
    "json": JSONFormatParser,
    "key_value": KeyValueParser,
    "csv": CSVFormatParser,
    "cef": CEFFormatParser,
    "regex": RegexFormatParser,
    "unknown": FallbackParser,
}


def get_parser(format_name: str) -> BaseFormatParser:
    parser_cls = BUILTIN_PARSERS.get(format_name, FallbackParser)
    return parser_cls()


__all__ = [
    "BUILTIN_PARSERS",
    "get_parser",
    "BaseFormatParser",
    "SyslogParser",
    "JSONFormatParser",
    "KeyValueParser",
    "CSVFormatParser",
    "CEFFormatParser",
    "RegexFormatParser",
    "FallbackParser",
]
