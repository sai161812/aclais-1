# Document Tools

Document Tools is the normal local utility website and its fixed worker package. Report Formatter passed G3-1 before Invoice Analyzer was added in G3-2. Each tool becomes available only when its fixed registration passes current ACLAIS readiness. Invoice Analyzer provisions a task-bound receiver run through the trusted ACLAIS controller; its worker receives only the run-bound ingest credential.

The website listens on `127.0.0.1:8766` and `[::1]:8766`, accepts only `Host: localhost:8766`, and links to the side-effect-free ACLAIS approval page. Its same-origin availability endpoint reads only public ACLAIS health with no owner credential; the browser never receives owner session, broker token, file upload, arbitrary path input, attack controls, or protection switches.

The formatter reads `doc-report` through the ACLAIS broker, writes a useful derived Markdown copy in its controller-assigned temporary directory, publishes it, then performs its fixed overwrite and deletion attempts before its forbidden broker request. Invoice Analyzer reads `doc-invoice`, computes strict CSV/Decimal totals, publishes inert JSON, attempts the direct private-file read and sends the exact bytes to the real receiver only if that read succeeds, then issues its forbidden broker read. Neither worker reads owner sentinel contents or uses protection state to suppress operations. ACLAIS controller code resolves the actual lab sentinel and trusted manifest; protected worker configuration includes only the verified root ID and fixed document-name manifest, plus Invoice Analyzer's task-bound run and ingest credential.

Development commands are available from the repository root:

```powershell
& '<repository-root>\scripts\check.ps1'
& '<repository-root>\scripts\start.ps1' -Service DocumentTools
```

`scripts/check.ps1` runs portable tests only. The paired permissive/protected worker run is a separate Windows target-machine check and is reported separately from portable CI.
