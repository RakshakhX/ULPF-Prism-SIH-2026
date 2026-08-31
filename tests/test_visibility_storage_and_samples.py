import json
from pathlib import Path

import pytest

from src.validation.validate_unified_event import validate_file

VISIBILITY_SAMPLES_DIR = Path("examples/visibility")
OPENSEARCH_TEMPLATE_PATH = Path("schemas/opensearch-index-template-v1.json")

EXPECTED_VISIBILITY_SAMPLES = {
    "cisco_asa_firewall_deny.json",
    "suricata_ids_threat_alert.json",
    "juniper_router_acl_deny.json",
}


def test_opensearch_index_template_structure_and_coverage() -> None:
    assert OPENSEARCH_TEMPLATE_PATH.exists(), "OpenSearch index template file must exist"
    data = json.loads(OPENSEARCH_TEMPLATE_PATH.read_text(encoding="utf-8"))

    assert "index_patterns" in data
    assert "ulpf-events-v1-*" in data["index_patterns"]
    assert "template" in data

    mappings = data["template"]["mappings"]["properties"]
    assert mappings["schema_version"]["type"] == "keyword"
    assert mappings["time"]["properties"]["observed_at"]["type"] == "date"
    assert mappings["source"]["properties"]["ip"]["type"] == "ip"
    assert mappings["destination"]["properties"]["ip"]["type"] == "ip"
    assert mappings["severity"]["properties"]["normalized"]["type"] == "byte"
    assert mappings["action"]["properties"]["normalized"]["type"] == "keyword"
    assert mappings["observer"]["properties"]["vendor"]["type"] == "keyword"
    assert mappings["observer"]["properties"]["product"]["type"] == "keyword"
    assert mappings["extensions"]["type"] == "flattened"
    assert mappings["traceability"]["properties"]["raw_sha256"]["type"] == "keyword"


def test_exact_visibility_samples_exist() -> None:
    assert {
        path.name for path in VISIBILITY_SAMPLES_DIR.glob("*.json")
    } == EXPECTED_VISIBILITY_SAMPLES


@pytest.mark.parametrize("filename", sorted(EXPECTED_VISIBILITY_SAMPLES))
def test_visibility_samples_are_valid_unified_events(filename: str) -> None:
    sample_file = VISIBILITY_SAMPLES_DIR / filename
    result = validate_file(sample_file)
    assert result.valid, f"Validation failed for {filename}: {result.issues}"


def test_cisco_sample_specific_contract() -> None:
    cisco_file = VISIBILITY_SAMPLES_DIR / "cisco_asa_firewall_deny.json"
    data = json.loads(cisco_file.read_text(encoding="utf-8"))
    assert data["observer"]["vendor"] == "cisco"
    assert data["observer"]["product"] == "asa"
    assert data["action"]["normalized"] == "deny"
    assert data["action"]["outcome"] == "failure"
    assert data["event"]["category"] == "network"


def test_suricata_sample_specific_contract() -> None:
    suricata_file = VISIBILITY_SAMPLES_DIR / "suricata_ids_threat_alert.json"
    data = json.loads(suricata_file.read_text(encoding="utf-8"))
    assert data["observer"]["product"] == "suricata"
    assert data["event"]["category"] == "intrusion_detection"
    assert "threat" in data
    assert data["threat"]["category"] == "exploit"
    assert data["threat"]["confidence"] >= 0.9
    assert data["action"]["normalized"] == "detect"


def test_juniper_sample_specific_contract() -> None:
    juniper_file = VISIBILITY_SAMPLES_DIR / "juniper_router_acl_deny.json"
    data = json.loads(juniper_file.read_text(encoding="utf-8"))
    assert data["observer"]["vendor"] == "juniper"
    assert data["observer"]["type"] == "router"
    assert data["action"]["normalized"] == "deny"
    assert "extensions" in data
    assert "juniper" in data["extensions"]
