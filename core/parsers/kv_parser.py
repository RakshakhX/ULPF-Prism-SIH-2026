"""
core/parsers/kv_parser.py

Parses key=value logs, common with firewalls/CEF-adjacent vendors, e.g.:

  src=10.1.1.1 dst=10.2.2.2 spt=443 dpt=51234 action="allow" msg="TCP connection"

Supports quoted values (with embedded spaces) and unquoted tokens.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser

# key=value, where value is either a "quoted string" or a run of non-space chars
_KV_RE = re.compile(
    r'(?P<key>[A-Za-z0-9_.\-]+)=(?:"(?P<qval>[^"]*)"|(?P<val>[^\s]+))'
)


class KeyValueParser(BaseFormatParser):
    format_name = "key_value"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        return bool(_KV_RE.search(raw_payload))

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        matches = list(_KV_RE.finditer(raw_payload))
        if not matches:
            raise FormatParsingError("No key=value pairs found in payload")

        result: Dict[str, Any] = {}
        for m in matches:
            key = m.group("key")
            value = m.group("qval") if m.group("qval") is not None else m.group("val")
            result[key] = value
        return result
