# Live startup restoration - 2026-10-30

## Observed failure

The protected controller refused startup during publication reconciliation. The standalone doctor passed identity, permissions, installed code/fixture integrity, credential retrieval, Job Object configuration and database integrity, but that prerequisite result did not establish API startup. The database referred to 44 committed outputs whose exact files were retained in quarantine. One output row had been marked inconsistent after its expected destination was absent.

## Reviewed repair and preservation

The ordinary Windows owner verified the owned sentinel and passed the actual idle Windows boundary check. An exclusive controller/operator lease and no-active-task assertion guarded the repair. A unique protected database backup had an identical schema and every table's rows identical except one output row's `state` and `updated_at` fields. No tasks, events, owner sessions, credentials or request records were absent from the snapshot.

The current failed database and the verified snapshot were backed up into the protected raw recovery archive. Each of the 44 retained files was checked against the journal-derived destination, SHA-256 and byte count before a no-replace move. All corresponding destinations were absent; reparse points were rejected. Another 43 unrelated test outputs were retained in that archive with their original paths and hashes recorded locally. No receipt or receiver payload was modified or removed.

After restoring the verified snapshot, SQLite integrity, journal reconciliation, unknown-file scanning and independent published-output reads all passed. Output states were 44 published and one aborted. The preserved historical counts were 50 tasks, 591 events, 58 owner sessions and 48 worker-credential records. The failed state remains in the protected recovery evidence; no triggers were disabled or inconsistency flag edited by SQL.

## Actual startup and HTTP results

- `scripts/aclais.ps1 -Action start` reached `Application startup complete` and listened on its fixed owner origin.
- ACLAIS `/api/health`: HTTP 200, ready, protection ready, both installed tool checks passing.
- Document Tools website: HTTP 200.
- Document Tools `/availability.json`: HTTP 200, ready, Report Formatter true and Invoice Analyzer true.
- Receiver `/health`, requested with `curl.exe --noproxy "*" -g`: HTTP 200, ready.
- An unauthenticated request for the owner page: HTTP 401 as required. Existing owner sessions were preserved; no credential was printed.

Implementation-input digest remains `81cf246c2dbf9b7ca78820b27115c1c85b7a34a711df6a156cf6b6807c6eef63` across 183 files. This repair exercised the actual provisioned Windows machine and production startup paths. It does not establish a new G4 PASS or relabel an unrun enforcement suite as passed. Raw recovery snapshots, file paths, hashes, credentials and receipt content are excluded from this report and Git.
