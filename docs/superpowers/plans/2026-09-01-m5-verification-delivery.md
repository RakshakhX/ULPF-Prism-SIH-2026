# Milestone 5: Scale Evidence, Documentation, and Competition Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce honest performance evidence, full quality gates, synchronized project documentation, and reproducible SIH evaluation materials.

**Architecture:** Benchmarks emit machine-readable evidence and separate measured results from projections. CI runs the complete maintained codebase, while the final demo proves one event’s evidence, parsing, normalization, persistence, provenance, and exports without hidden setup.

**Tech Stack:** Python 3.11, pytest, Ruff, psutil, Redpanda metrics, Docker Compose, Markdown, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Global Constraints

- Never claim that the student prototype processed billions of events per day.
- Report hardware, duration, event size, concurrency, EPS, p50/p95/p99 latency, CPU, memory, retry, DLQ, and lag.
- Capacity projections expose every multiplier and assumption.
- README, architecture, API, demo, and air-gap docs must describe implemented behavior only.
- Final completion requires fresh test/lint/config evidence.

---

### Task 1: Reproducible benchmark and projection report

**Files:**
- Create: `benchmarks/generate_events.py`
- Create: `benchmarks/run_local.py`
- Create: `benchmarks/report.py`
- Create: `benchmarks/config.example.json`
- Create: `tests/test_benchmark_reporting.py`
- Modify: `files/load_gen.py`
- Modify: `files/benchmark_metrics.py`

**Interfaces:**
- Consumes: benchmark configuration and pipeline endpoint/broker.
- Produces: `artifacts/benchmarks/<run-id>/metrics.json`, `report.md`, and explicit `projected_eps(nodes, workers_per_node, efficiency_factor)` calculations.

- [ ] **Step 1: Write failing statistics and honesty tests**

```python
def test_projection_exposes_assumptions():
    report = build_report(measured_eps=2500, nodes=8, workers_per_node=4, baseline_workers=2, efficiency_factor=0.70)
    assert report.projected_eps == 2500 * (8 * 4 / 2) * 0.70
    assert report.claim_type == "projection"

def test_report_contains_required_metrics(sample_metrics):
    report = build_report_from_samples(sample_metrics)
    assert {"eps", "latency_ms_p50", "latency_ms_p95", "latency_ms_p99", "cpu_percent", "memory_mb", "retry_count", "dead_letter_count", "consumer_lag"} <= report.metrics.keys()
```

- [ ] **Step 2: Confirm report API is missing**

Run: `pytest tests/test_benchmark_reporting.py -q`

Expected: missing `benchmarks.report` imports.

- [ ] **Step 3: Implement deterministic fixtures, measurements, and projections**

The generator cycles Cisco/Fortinet/Syslog/Suricata fixtures and configurable event sizes. The runner records environment metadata, warm-up and measurement durations, per-stage counts, latency samples, CPU/memory, retries, DLQ, and lag. The report labels local values `measured` and all billion/day comparisons `projected`; one billion/day average is calculated as `1_000_000_000 / 86_400 ≈ 11_574 EPS` before burst/headroom assumptions.

- [ ] **Step 4: Verify reporting and run a bounded smoke benchmark**

Run: `pytest tests/test_benchmark_reporting.py -q && python -m benchmarks.run_local --config benchmarks/config.example.json --duration 10 --output artifacts/benchmarks/smoke && ruff check benchmarks tests/test_benchmark_reporting.py`

Expected: tests pass and smoke output contains both JSON and Markdown evidence.

- [ ] **Step 5: Commit source and sample report, excluding bulky run data**

```bash
git add benchmarks tests/test_benchmark_reporting.py files .gitignore
git commit -m "perf: add reproducible scale evidence reporting"
```

### Task 2: Complete CI and release-quality gates

**Files:**
- Create: `.github/workflows/quality.yml`
- Create: `.github/workflows/integration.yml`
- Modify: `pyproject.toml`
- Create: `scripts/verify_release.sh`
- Create: `tests/test_ci_contract.py`

**Interfaces:**
- Consumes: repository checkout.
- Produces: unit/static CI on every PR; opt-in/container integration workflow; `scripts/verify_release.sh` as the canonical local gate.

- [ ] **Step 1: Write failing workflow coverage tests**

```python
def test_quality_workflow_checks_all_python_roots(workflow_text):
    assert "ruff check core src source_packs tests main.py benchmarks scripts" in workflow_text
    assert "pytest -m 'not integration'" in workflow_text
```

- [ ] **Step 2: Confirm workflows are incomplete or absent**

Run: `pytest tests/test_ci_contract.py -q`

Expected: required workflow commands are absent.

- [ ] **Step 3: Implement pinned CI and release script**

Quality workflow installs the package with dev/export/integration dependencies, runs Ruff and non-container pytest, validates Compose, and builds the image. Integration workflow starts the stack, waits for readiness, runs `pytest -m integration`, captures service logs on failure, and tears down. `verify_release.sh` runs the same checks in fail-fast order.

- [ ] **Step 4: Run the local release gate**

Run: `bash scripts/verify_release.sh`

Expected: all available unit/static/build checks pass; if Docker is unavailable, the script exits nonzero with an explicit prerequisite message.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows pyproject.toml scripts/verify_release.sh tests/test_ci_contract.py
git commit -m "ci: enforce complete platform quality gates"
```

### Task 3: Documentation synchronization and two-minute demo

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Create: `docs/api.md`
- Create: `docs/demo-script.md`
- Create: `docs/scalability.md`
- Create: `docs/traceability.md`
- Modify: `docs/source-pack-guide.md`
- Modify: `docs/development-workflow.md`
- Modify: `docs/component-boundaries.md`
- Create: `scripts/demo.sh`
- Modify: `tests/test_documentation_contract.py`

**Interfaces:**
- Consumes: implemented commands, endpoints, services, fixtures, and benchmark outputs.
- Produces: newcomer setup, architecture narrative, exact demo command, API reference, provenance walkthrough, and scale limitations.

- [ ] **Step 1: Expand failing documentation contract tests**

```python
def test_readme_names_real_primary_stack(readme):
    for term in ["Redpanda", "ClickHouse", "Grafana", "Parquet", "air-gapped"]:
        assert term in readme

def test_demo_has_no_network_install_commands():
    demo = Path("scripts/demo.sh").read_text()
    assert "pip install" not in demo
    assert "curl https://" not in demo
```

- [ ] **Step 2: Confirm docs are stale**

Run: `pytest tests/test_documentation_contract.py -q`

Expected: current README/architecture omit completed components or demo script is absent.

- [ ] **Step 3: Write implementation-matched docs and a deterministic demo**

The two-minute script starts/validates the stack, ingests one valid and one malformed Cisco log, captures event ID/raw hash, queries the normalized event from persistent storage, shows provenance and quality, triggers JSONL/Parquet export, verifies the manifest, and prints Grafana/OpenSearch URLs. It must stop with a useful error if prerequisites are missing.

- [ ] **Step 4: Verify docs, demo shell, and links**

Run: `pytest tests/test_documentation_contract.py -q && bash -n scripts/demo.sh && python -m src.validation.schema_validation examples/unified_events`

Expected: documentation contracts and shell syntax pass; examples remain schema-valid.

- [ ] **Step 5: Commit**

```bash
git add README.md docs scripts/demo.sh tests/test_documentation_contract.py
git commit -m "docs: finalize architecture and competition demo"
```

### Task 4: Final full-system verification and cleanup

**Files:**
- Modify only files identified by failing verification; do not add features.
- Create: `docs/verification-report.md`

**Interfaces:**
- Consumes: completed milestones 1–5.
- Produces: fresh evidence for tests, lint, Compose, image build, integration, demo, and known limitations.

- [ ] **Step 1: Run all static and unit gates**

Run: `ruff check core src source_packs tests main.py benchmarks scripts && pytest -m 'not integration' -q && git diff --check`

Expected: zero Ruff findings, all non-integration tests pass, no whitespace errors.

- [ ] **Step 2: Run container and integration gates**

Run: `docker compose config && docker compose build && docker compose up -d --wait && pytest -m integration -q`

Expected: valid Compose, successful builds, healthy services, passing integration tests.

- [ ] **Step 3: Run the final demonstration and offline verifier**

Run: `bash scripts/demo.sh && bash scripts/offline/build_bundle.sh 0.1.0 artifacts/offline/latest && python scripts/offline/verify_bundle.py artifacts/offline/latest`

Expected: end-to-end demonstration succeeds and every offline artifact checksum verifies.

- [ ] **Step 4: Record evidence and limitations**

Write exact date, commit, host description, commands, counts, benchmark run ID, outcomes, and any environmental skips to `docs/verification-report.md`. Do not convert a skipped Docker/benchmark check into a pass.

- [ ] **Step 5: Commit verification-only fixes and report**

```bash
git add docs/verification-report.md
git add -u
git commit -m "chore: verify full ULPF competition release"
```

- [ ] **Step 6: Request final code review**

Use `superpowers:requesting-code-review`, address only verified findings through `superpowers:receiving-code-review`, rerun the full relevant gates, and then use `superpowers:finishing-a-development-branch` for the merge decision.
