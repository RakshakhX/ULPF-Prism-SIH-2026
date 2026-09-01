# ULPF Prism Full Platform Implementation Plan Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the approved ULPF Prism architecture through five independently testable milestones.

**Architecture:** Work proceeds dependency-first: canonical contracts and collection, streamed processing, persistent visibility, integrations/offline packaging, then scale evidence and final delivery. Each milestone remains green and reviewable before the next begins.

**Tech Stack:** Python 3.11, Pydantic v2, Redpanda, ClickHouse, Grafana, OpenSearch integration, PyArrow/Parquet, Docker Compose, pytest, Ruff.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Global Constraints

- Implement the plans in order because later interfaces depend on earlier contracts.
- Use test-driven development and focused commits for every task.
- Do not silently drop or mutate raw evidence.
- Do not claim measured billion-event production capacity.
- Keep OpenSearch positioning accurate: it is a search/SIEM-integration target.
- Do not begin a later milestone while the current milestone's focused gates are red.

---

- [ ] **Milestone 1:** Execute `docs/superpowers/plans/2026-09-01-m1-contracts-collection.md`.
- [ ] **Checkpoint 1:** Review canonical contracts, archive-first order, bounded state, and collector tests.
- [ ] **Milestone 2:** Execute `docs/superpowers/plans/2026-09-01-m2-streamed-pipeline.md`.
- [ ] **Checkpoint 2:** Demonstrate canonical Cisco/Fortinet/Syslog paths, retry, DLQ, replay, and no startup sample mutation.
- [ ] **Milestone 3:** Execute `docs/superpowers/plans/2026-09-01-m3-visibility.md`.
- [ ] **Checkpoint 3:** Demonstrate ClickHouse persistence, Suricata cross-vendor data, provenance queries, and provisioned Grafana.
- [ ] **Milestone 4:** Execute `docs/superpowers/plans/2026-09-01-m4-integrations-offline.md`.
- [ ] **Checkpoint 4:** Demonstrate serializers, OpenSearch delivery accounting, Parquet read-back, complete Compose, and offline verification.
- [ ] **Milestone 5:** Execute `docs/superpowers/plans/2026-09-01-m5-verification-delivery.md`.
- [ ] **Checkpoint 5:** Run full release gates, record honest benchmark evidence, execute the two-minute demo, and request final code review.
