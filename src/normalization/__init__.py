"""Public API for registry-driven universal event normalization."""

from src.normalization.mappings import (
    CiscoASAMapping,
    FortinetFortigateMapping,
    GenericLinuxSyslogMapping,
)
from src.normalization.normalizer import UniversalNormalizer
from src.normalization.registry import NormalizationRegistry


def default_registry() -> NormalizationRegistry:
    registry = NormalizationRegistry()
    registry.register(CiscoASAMapping())
    registry.register(FortinetFortigateMapping())
    registry.register(GenericLinuxSyslogMapping())
    return registry


__all__ = ["NormalizationRegistry", "UniversalNormalizer", "default_registry"]
