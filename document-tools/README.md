# Document Tools

Document Tools is the normal local utility website and its fixed worker package. The Report Formatter is the only production worker in this checkpoint. Invoice Analyzer remains unavailable until Report Formatter passes its protected and permissive fixture checks.

The website listens on `127.0.0.1:8766` and `[::1]:8766`, accepts only `Host: localhost:8766`, and links to the side-effect-free ACLAIS approval page. It has no owner session, broker token, file upload, arbitrary path input, attack controls, or protection switches.

The formatter reads `doc-report` through the ACLAIS broker, writes a useful derived Markdown copy in its controller-assigned temporary directory, publishes it, then performs its fixed overwrite and deletion attempts before its forbidden broker request. ACLAIS controller code resolves the actual lab sentinel and trusted manifest; the worker receives only the verified root ID and the fixed four-document filename manifest in its protected task configuration. It never reads owner sentinel contents or protected originals as a precondition to those attempts.

Development commands are available from the repository root:

```powershell
& '<repository-root>\scripts\check.ps1'
& '<repository-root>\scripts\start.ps1' -Service DocumentTools
```

`scripts/check.ps1` runs portable tests only. The paired permissive/protected worker run is a separate Windows target-machine check and is reported separately from portable CI.
