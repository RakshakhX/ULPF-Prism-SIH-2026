"""Vendor-neutral output adapter APIs."""

from src.integrations.base import DeliveryResult, OutputAdapter
from src.integrations.cef import serialize_cef
from src.integrations.json_adapter import JsonOutputAdapter, serialize_json
from src.integrations.opensearch import OpenSearchAdapter, TransportResponse
from src.integrations.syslog import serialize_rfc5424
from src.integrations.worker import AdapterDeliveryWorker, DeliveryDecision

__all__ = [
    "AdapterDeliveryWorker",
    "DeliveryDecision",
    "DeliveryResult",
    "JsonOutputAdapter",
    "OutputAdapter",
    "OpenSearchAdapter",
    "TransportResponse",
    "serialize_cef",
    "serialize_json",
    "serialize_rfc5424",
]
