# ACLAIS — coding-agent build pack
Version 1.1 • 28 October 2026 • specification, not implemented software

## Read first
Build a small, real Windows security prototype with two natural document workflows. There must be no attack button, demo tab, fake telemetry, or cosmetic enforcement. Real file operations must be attempted and denied by independently testable boundaries.

Use [`IMPLEMENTATION_CHECKPOINTS.md`](../IMPLEMENTATION_CHECKPOINTS.md) to sequence readiness A0 and implementation checkpoints A1–A10. This plan does not change the component order or permit later components to begin before their specified gate.

Three deliverable components:
1. ACLAIS: controller, broker, Windows worker launcher, protected store, evidence, premium dashboard.
2. Local receiver: separate process and independently persisted receipts.
3. Document Tools: separate website containing Report Formatter and Invoice Analyzer, plus their worker programs.

Build order is intentionally ACLAIS → receiver → Document Tools. Build and test one component completely before starting production implementation of the next. Test probes and contract fixtures are permitted inside an earlier component's tests; they must not become a disguised implementation of a later component.

## Read order and authority
1. [01_MASTER_WORKFLOW.md](01_MASTER_WORKFLOW.md): purpose, scope, workflows, architecture.
2. [02_SHARED_CONTRACTS.md](02_SHARED_CONTRACTS.md): authoritative names, APIs, states, data and error semantics.
3. Current component guide: [03_BUILD_ACLAIS.md](03_BUILD_ACLAIS.md), [04_BUILD_RECEIVER.md](04_BUILD_RECEIVER.md), then [05_BUILD_DOCUMENT_TOOLS.md](05_BUILD_DOCUMENT_TOOLS.md).
4. [06_UI_DESIGN.md](06_UI_DESIGN.md): authoritative visual and interaction rules.
5. [07_VERIFICATION_AND_HANDOFF.md](07_VERIFICATION_AND_HANDOFF.md): gates, integration and rehearsal.
6. [08_CODING_AGENT_PROMPTS.md](08_CODING_AGENT_PROMPTS.md): execution discipline and copyable prompts.

If documents appear inconsistent, stop the affected implementation, identify the conflict, and reconcile all affected documents before coding. Contracts own wire semantics; master owns scope; component guides own implementation details; design guide owns appearance. No document may weaken an enforcement requirement. Record decisions in DECISIONS.md.

## Target and stack
Target: Windows 11, NTFS, local accounts, administrative access for initial provisioning only, Chrome or Edge. Runtime controller should run as the ordinary owner account, not Administrator. Dedicated non-administrator AclaisWorker identity executes workers. A different identity is an actual boundary; a subprocess under the controller's identity is not.

Backend: Python with FastAPI/Pydantic, SQLite, pytest; Windows API bindings through a small audited pywin32/ctypes adapter. UI: React + TypeScript + Vite, CSS design tokens, locally installed icons. Browser tests: Playwright. Record installed versions and lock dependencies; do not guess latest versions. No LLM/API key, cloud backend, external fonts, PDF/OCR pipeline, Docker dependency, kernel driver, or browser extension.

Inputs: seeded UTF-8 Markdown and CSV only. Use a real deterministic formatter and real CSV extraction. Small supported input scope is deliberate.

Repository layout: `aclais/` contains the ACLAIS backend, frontend, security implementation, component tests, and component-specific configuration; `receiver/` contains the later receiver service and its component tools/tests; `document-tools/` contains the later website, Report Formatter, Invoice Analyzer, and component tests; `shared/` contains shared schemas and minimal protocol definitions. Root `tests/` is for cross-component integration and acceptance only; root `scripts/` is for whole-system orchestration. Keep component source, dependencies, tests, assets, and configuration in their assigned folders. Do not add receiver or Document Tools production files before their prerequisite gates pass. Keep one Git repository with no component submodules or separate histories. Keep the supplied specification pack in its existing `docs/` arrangement; do not move it into `docs/spec/`. Root `AGENTS.md` points to this specification; this pack itself is not an installed skill.

Required tracking files: BUILD_STATUS.md, DECISIONS.md, IMPLEMENTATION_CHECKPOINTS.md, RUNBOOK.md. Start every gate as NOT_STARTED. Distinguish PASS, FAIL, BLOCKED, NOT_RUN. Never mark Windows enforcement PASS from Linux tests or mocked API calls.

## Execution rule
Within a component, proceed autonomously through its steps and fixes. Advance only after its gate has a dated evidence report and every mandatory check passes. Do not repeatedly ask permission for routine work already requested. If the environment cannot execute a mandatory check, report BLOCKED with the exact missing prerequisite; do not silently replace security with UI simulation.

This is a one-day target, not a guarantee. Cut optional animation and convenience features before cutting isolation, independent evidence, or either scenario.
