"""
core/exceptions.py

All engine-level failures funnel through these so the engine can decide,
in one place, what is recoverable (-> fallback parsing) versus fatal.
"""


class ULPFError(Exception):
    """Base class for all ULPF engine errors."""


class SourceDetectionError(ULPFError):
    """Raised when source detection logic itself fails (not just 'no match')."""


class SourcePackLoadError(ULPFError):
    """Raised when a Source Pack manifest or module fails to load."""


class SourcePackValidationError(ULPFError):
    """Raised when a Source Pack manifest is malformed or missing required keys."""


class FormatParsingError(ULPFError):
    """Raised by a format parser when it cannot parse a payload it was given."""


class FieldExtractionError(ULPFError):
    """Raised when field-mapping rules fail against parsed data."""
