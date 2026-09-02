from pathlib import Path

from core.registry import SourcePackRegistry
from source_packs.generic_linux_syslog.pack import GenericLinuxSyslogPack
from src.contracts import ParseStatus, RawEventEnvelope


def write_manifest(root: Path, implementation: str) -> None:
    pack_dir = root / "demo_syslog"
    pack_dir.mkdir()
    (pack_dir / "manifest.yaml").write_text(
        f"""
implementation: "{implementation}"
pack:
  vendor: Generic
  product: Demo Syslog
  pack_version: 1.0.0
detection:
  priority: 10
  rules:
    - type: keyword
      target: raw_payload
      any_of: ["sshd"]
format:
  type: syslog
fields:
  - name: message
    source: message
    required: true
""".strip(),
        encoding="utf-8",
    )


def test_registry_instantiates_manifest_implementation(tmp_path: Path) -> None:
    write_manifest(
        tmp_path,
        "source_packs.generic_linux_syslog.pack:GenericLinuxSyslogPack",
    )

    registry = SourcePackRegistry(tmp_path)

    assert isinstance(registry.packs[0], GenericLinuxSyslogPack)


def test_registry_routes_canonical_envelope_through_declared_pack(tmp_path: Path) -> None:
    write_manifest(
        tmp_path,
        "source_packs.generic_linux_syslog.pack:GenericLinuxSyslogPack",
    )
    registry = SourcePackRegistry(tmp_path)
    raw = RawEventEnvelope.from_bytes(
        b"<34>Oct 11 22:14:15 host sshd[42]: Failed password",
        source_id="linux-1",
        transport="udp",
    )

    pack = registry.match(raw)
    assert pack is not None
    parsed = pack.parse(raw)

    assert parsed.status is ParseStatus.SUCCESS
    assert parsed.raw_event == raw
    assert parsed.extracted_fields["message"] == "Failed password"


def test_invalid_manifest_does_not_prevent_valid_pack_loading(tmp_path: Path) -> None:
    invalid_dir = tmp_path / "invalid"
    invalid_dir.mkdir()
    (invalid_dir / "manifest.yaml").write_text("- not-a-mapping\n", encoding="utf-8")
    write_manifest(
        tmp_path,
        "source_packs.generic_linux_syslog.pack:GenericLinuxSyslogPack",
    )

    registry = SourcePackRegistry(tmp_path)

    assert [pack.pack_id for pack in registry.packs] == ["demo_syslog"]
