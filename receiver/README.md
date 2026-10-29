# ACLAIS local receiver

The receiver is an independent process with its own SQLite database, run-bound
ingest credentials, and protected receipt files. It listens only on
`[::1]:8767`; it never binds the ACLAIS owner-cookie host. Its records report
what this receiver observed. They do not change an ACLAIS task decision or prove
that an attack was blocked.

The normal Windows store is `C:\ACLAIS-Lab\state\receiver`, outside this Git
checkout. `admin.token`, the database, staged payloads, committed receipts and
quarantine are protected there. Initialize once with
`receiver/scripts/receiver.ps1 -Action init`, then start in the foreground with
`scripts/start.ps1 -Service Receiver`. Stop with Ctrl+C. The generated admin
credential is never printed; ACLAIS reads it from the same owner-only runtime
directory when collecting evidence. The owner CLI exposes metadata only; G2 has no reset action and preserves stored history. A safe offline archive/reset remains deferred until G4 provides a trusted way to verify that no associated ACLAIS task is active.

Run `receiver/scripts/check.ps1` for portable component checks. The repository
check also runs the real IPv6 HTTP adapter integration in `tests/`. Raw test
payloads and credentials are temporary and are not uploaded by CI.
