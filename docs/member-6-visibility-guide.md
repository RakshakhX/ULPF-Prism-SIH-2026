# Member 6 guide — analytical storage and visibility

## Assignment

GitHub user `hridayjain886-bit` owns Epic 5: analytical storage and unified visibility. The goal is to make valid `UnifiedEvent` records searchable across vendors and to expose their quality, provenance, and framework-health information. This guide organizes the work; it does not prescribe the final storage or dashboard design.

## Ownership boundary

You own the analytical storage model, normalized-event sink, queries, dashboard definitions, raw-evidence drill-down experience, Suricata sample data, and Epic 5 demonstration. You consume the shared `UnifiedEvent` contract; you do not rename or privately redefine its fields.

Do not implement collection, raw-event storage, source-specific parsing, stream transport, or SIEM/data-lake exporters. Coordinate those boundaries with Epics 1, 2, 4, and 6 respectively.

## First-day checklist

1. Confirm that you can open the private repository, issues, and project board.
2. Install Git and Python 3.11 or newer.
3. Clone the repository and enter it:

   ```bash
   git clone https://github.com/RakshakhX/ULPF-Prism-SIH-2026.git
   cd ULPF-Prism-SIH-2026
   ```

4. Configure your own Git identity if needed:

   ```bash
   git config user.name "Your Name"
   git config user.email "your-github-email@example.com"
   ```

5. Create the environment and verify the current baseline:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements-dev.txt
   python -m pytest
   ```

   On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

6. Read, in order: [UnifiedEvent reference](event-schema.md), [architecture](architecture.md), [component boundaries](component-boundaries.md), [engineering conventions](engineering-conventions.md), and [contributing rules](../CONTRIBUTING.md).
7. Validate two records before designing storage:

   ```bash
   python -m src.validation.validate_unified_event examples/unified_events/firewall_allow.json
   python -m src.validation.validate_unified_event examples/unified_events/ids_threat_detected.json
   ```

8. Comment on Epic 5 with what you read, what you will start, and any dependency that is unclear.

## Suggested child issues

Create these as separate child issues under Epic 5. Finish and review one issue before starting the next.

### 1. `[STORAGE] Define the UnifiedEvent analytical model`

Work:

- Inventory every required and optional `UnifiedEvent` section.
- Define how nested values, extensions, quality information, and raw references are represented.
- Write the query requirements for time, vendor, device, category, action, severity, source/destination IP, and destination port.
- Record retention and prototype performance assumptions explicitly.
- Use existing valid and invalid fixtures as contract examples.

Done when:

- The model maps every schema field without silently dropping information.
- Raw evidence is referenced by `raw_event_id` and `raw_sha256`; it is not copied or altered accidentally.
- Gaurang reviews the `UnifiedEvent` mapping and Daksh reviews the raw-reference boundary.
- The design has automated contract tests or machine-checkable examples.

### 2. `[SINK] Store validated UnifiedEvent records in batches`

Work:

- Begin with validated JSON files so work can proceed before Epic 4 streaming is ready.
- Reject or quarantine invalid records instead of inserting them as valid data.
- Insert valid records in batches and report insertion errors.
- Preserve extensions, quality flags, timestamps, and traceability fields.
- Define a narrow input interface that Epic 4 can later call without changing the storage model.

Done when:

- All seven official example records can be inserted and queried.
- Reprocessing a known event has documented duplicate behavior based on `event.id`.
- A failed batch produces a visible error without silently losing accepted records.
- Automated storage tests pass using fictional data.

### 3. `[QUERY] Add cross-vendor investigation queries`

Work:

- Add query examples for time range, vendor, observer type, category, action, outcome, severity, IP address, and port.
- Demonstrate equivalent activity from more than one fictional vendor in one result.
- Include quality-warning, missing-field, and unknown-source queries.
- Include a provenance query returning raw ID, raw SHA-256, Source Pack, and parser versions.

Done when:

- Every query has a stated purpose and deterministic sample result.
- Queries use normalized fields rather than reparsing `event.message`.
- Query examples remain vendor-neutral except inside `extensions`.

### 4. `[VISIBILITY] Build the minimum unified-visibility dashboards`

Work:

- Build an overview view, event-search view, cross-vendor security view, data-quality view, and framework-health view.
- Include the panels listed in Epic 5, but start with a minimum demonstrable set before adding polish.
- Provide filters for time, vendor, device, IP, action, and severity.
- Show that a selected normalized event exposes provenance and the raw-evidence reference.
- Treat raw-event retrieval as an Epic 1 dependency; use an explicit placeholder contract until it exists.

Done when:

- A user can complete the Epic 5 investigation workflow from search to provenance.
- Panels distinguish event time from ingestion/processing health measurements.
- Unknown sources, parsing/quality warnings, throughput, and latency are visible.
- Dashboard definitions are version-controlled and reproducible offline.

### 5. `[DEMO] Prepare the Suricata visibility dataset and script`

Work:

- Prepare 20 fictional valid Suricata-style normalized records and 5 incomplete or malformed cases.
- Cover multiple event types and use only documentation-safe IP addresses and invented identifiers.
- Write expected storage/query/dashboard outcomes before recording the demo.
- Create a short script showing ingestion, filtering, cross-vendor comparison, quality visibility, and provenance.

Done when:

- Valid records pass the public validator and malformed cases fail for documented reasons.
- No real organization, credential, personal data, or production log is committed.
- Screenshots and the demonstration can be reproduced from repository files in an offline environment.

## Dependency order

- Epic 3 provides the schema, validator, and examples. Do not copy them into Epic 5; import or consume the shared files after the Epic 3 branch is merged.
- Epic 1 must define how a raw reference is resolved. Until then, store and display the reference fields without inventing a second raw-event contract.
- Epic 4 must define the transported-event interface. Build the sink against validated local records first, then add the streaming adapter as a small integration change.
- Epic 6 consumes normalized records and raw references for exports. Coordinate field expectations, but keep exporter code outside Epic 5.

If a dependency blocks implementation, move the child issue to **Blocked**, name the required owner and decision, and continue with an independent child issue where possible.

## Git workflow for every child issue

Do not commit directly to `main`.

```bash
git switch main
git pull origin main
git switch -c feature/issue-N-short-name
```

Make one focused change, run its tests plus the full suite, and inspect your diff:

```bash
python -m pytest
git diff --check
git status --short
```

Stage only files belonging to the issue, commit them, push the feature branch, and open a pull request containing `Closes #N`, completed work, verification, and help needed. Contract changes need review from Gaurang and at least one affected component owner.

## Daily update

Post this short update on the project or team chat:

```text
Yesterday: completed work
Today: planned work
Blocked: required help or decision
```

Ask early when a shared field, raw-reference behavior, streaming input, or integration output is unclear. Do not solve a dependency by inventing a private incompatible contract.
