# Decisions

This log records decisions made while preparing the initial repository workflow. No application implementation decisions have been made.

## D-001 — Preserve the supplied specification pack

The nine files in `docs/` are the project authority for scope, contracts, component order, interface behavior, and verification. Keep the three components in this repository and implement only the explicitly requested checkpoint.

## D-002 — Use the explicitly supplied GitHub repository

The user supplied `https://github.com/sai161812/aclais-1.git`. Authenticated GitHub metadata verifies owner `sai161812`, repository `aclais-1`, public visibility, and default branch `main`. The repository has no branches or commits, so create a documentation-only baseline on `main` before creating `aclais-prototype`. Do not create another repository or replace a remote.

## D-003 — Keep this checkpoint documentation-only

The current work is limited to persistent agent instructions, build status, decisions, Git workflow notes, and ignore rules. Application features and enforcement code remain unstarted until their mandatory prerequisites are met.

## D-004 — Track safe templates and summaries; ignore sensitive runtime material

Ignore credentials, local environments, runtime databases, raw receipt payloads, generated confidential fixtures, unsanitized logs, and build/test output. Keep synthetic fixture templates and sanitized test summaries trackable.
