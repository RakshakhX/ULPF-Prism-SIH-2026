"""Safe manifest-driven Source Pack implementation loading."""

from __future__ import annotations

import importlib.util
import sys
from numbers import Real
from pathlib import Path
from types import ModuleType
from typing import Protocol

import yaml

from core.exceptions import SourcePackValidationError
from core.source_pack import SourcePackBase, validate_manifest
from src.contracts import ParsedEvent, RawEventEnvelope


class SourcePackProtocol(Protocol):
    pack_id: str
    priority: int

    def detect(self, envelope: RawEventEnvelope) -> bool | float: ...

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent: ...


def _load_local_class(
    manifest_path: Path,
    module_name: str,
    class_name: str,
):
    """Load an implementation only from the pack that declared it."""

    parts = module_name.split(".")
    pack_dir = manifest_path.parent.resolve()
    if len(parts) < 3 or parts[:2] != ["source_packs", pack_dir.name]:
        raise SourcePackValidationError(
            "implementation module must be inside its declaring source_packs directory"
        )

    module_path = pack_dir.joinpath(*parts[2:]).with_suffix(".py").resolve()
    if pack_dir not in module_path.parents or not module_path.is_file():
        raise SourcePackValidationError(
            f"implementation module does not exist inside the declaring pack: {module_name}"
        )

    package_name = ".".join(parts[:2])
    package = ModuleType(package_name)
    package.__path__ = [str(pack_dir)]  # type: ignore[attr-defined]
    package.__package__ = package_name
    sys.modules[package_name] = package

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise SourcePackValidationError(f"cannot create module spec for {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise SourcePackValidationError(
            f"implementation class does not exist: {module_name}:{class_name}"
        ) from exc


def _validate_runtime_pack(
    pack: object,
    manifest_path: Path,
    expected_pack_id: str,
) -> SourcePackProtocol:
    pack_id = getattr(pack, "pack_id", None)
    priority = getattr(pack, "priority", None)
    if not isinstance(pack_id, str) or not pack_id or pack_id != expected_pack_id:
        raise SourcePackValidationError(
            "Source Pack implementation pack_id must match pack.id or its directory name"
        )
    if isinstance(priority, bool) or not isinstance(priority, Real):
        raise SourcePackValidationError("Source Pack priority must be numeric")
    for method_name in ("detect", "parse"):
        if not callable(getattr(pack, method_name, None)):
            raise SourcePackValidationError(
                f"Source Pack implementation requires callable {method_name}()"
            )
    return pack  # type: ignore[return-value]


def load_source_pack(manifest_path: Path) -> SourcePackProtocol:
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SourcePackValidationError(f"cannot read Source Pack manifest: {exc}") from exc
    manifest = validate_manifest(manifest)

    implementation = manifest.get("implementation")
    expected_pack_id = manifest["pack"].get("id", manifest_path.parent.name)
    if not isinstance(expected_pack_id, str) or not expected_pack_id:
        raise SourcePackValidationError("Manifest pack.id must be a non-empty string")
    if not implementation:
        return _validate_runtime_pack(
            SourcePackBase(manifest_path), manifest_path, expected_pack_id
        )
    if not isinstance(implementation, str):
        raise SourcePackValidationError("implementation must be a module:class string")

    try:
        module_name, class_name = implementation.split(":", 1)
    except ValueError as exc:
        raise SourcePackValidationError("implementation must use module:class syntax") from exc
    try:
        implementation_class = _load_local_class(manifest_path, module_name, class_name)
        pack = implementation_class(manifest_path)
    except SourcePackValidationError:
        raise
    except Exception as exc:
        raise SourcePackValidationError(
            f"cannot load Source Pack implementation {implementation}"
        ) from exc
    return _validate_runtime_pack(pack, manifest_path, expected_pack_id)
