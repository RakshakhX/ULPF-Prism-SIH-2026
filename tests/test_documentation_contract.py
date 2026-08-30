from pathlib import Path

REQUIRED_FILES = {
    "README.md",
    "CONTRIBUTING.md",
    "docs/architecture.md",
    "docs/component-boundaries.md",
    "docs/development-workflow.md",
    "docs/engineering-conventions.md",
    "docs/event-schema.md",
    "docs/member-6-visibility-guide.md",
    "docs/research-basis.md",
    "docs/source-pack-guide.md",
}


def test_required_documentation_exists_and_is_not_empty() -> None:
    for filename in REQUIRED_FILES:
        content = Path(filename).read_text(encoding="utf-8")
        assert len(content.splitlines()) >= 8, filename


def test_engineering_conventions_lock_shared_names() -> None:
    content = Path("docs/engineering-conventions.md").read_text(encoding="utf-8")
    for name in (
        "RawEventEnvelope",
        "ParsedEvent",
        "UnifiedEvent",
        "SourcePack",
        "ValidationResult",
        "QualityFlags",
        "Traceability",
    ):
        assert name in content


def test_readme_contains_working_commands() -> None:
    content = Path("README.md").read_text(encoding="utf-8")
    assert "python -m pytest" in content
    assert "python -m src.validation.validate_unified_event" in content


def test_member_six_guide_locks_owner_and_work_sequence() -> None:
    content = Path("docs/member-6-visibility-guide.md").read_text(encoding="utf-8")
    assert "hridayjain886-bit" in content
    assert "Epic 5" in content
    assert "Suggested child issues" in content
    assert "Do not commit directly to `main`" in content
