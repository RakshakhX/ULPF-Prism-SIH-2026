"""Safe manifest-driven Source Pack implementation loading."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Protocol

import yaml

from core.exceptions import SourcePackValidationError
from core.source_pack import SourcePackBase
from src.contracts import ParsedEvent, RawEventEnvelope


class SourcePackProtocol(Protocol):
    pack_id: str
    priority: int

    def detect(self, envelope: RawEventEnvelope) -> bool | float: ...

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent: ...


def load_source_pack(manifest_path: Path) -> SourcePackProtocol:
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SourcePackValidationError(f"cannot read Source Pack manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SourcePackValidationError("Source Pack manifest must be a YAML mapping")

    implementation = manifest.get("implementation")
    if not implementation:
        return SourcePackBase(manifest_path)

    try:
        module_name, class_name = implementation.split(":", 1)
    except ValueError as exc:
        raise SourcePackValidationError("implementation must use module:class syntax") from exc
    if not module_name.startswith("source_packs."):
        raise SourcePackValidationError("implementation module must be beneath source_packs")

    try:
        implementation_class = getattr(importlib.import_module(module_name), class_name)
        pack = implementation_class(manifest_path)
    except Exception as exc:
        raise SourcePackValidationError(
            f"cannot load Source Pack implementation {implementation}"
        ) from exc

    for attribute in ("pack_id", "priority", "detect", "parse"):
        if not hasattr(pack, attribute):
            raise SourcePackValidationError(
                f"Source Pack implementation is missing required attribute: {attribute}"
            )
    return pack
