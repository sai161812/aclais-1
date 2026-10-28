# Private verification probes

These scripts are test-only and are not registered as production tools, packaged with the application, exposed by routes/UI, or reused as the later hostile Document Tools workers.

- `a2_root_guard_probe.ps1` exercises missing, unowned, mismatched, interrupted owned-root initialization using temporary synthetic directories, and confirms that a known Windows profile reparse point is rejected without changing it.
- `windows_a2_access_probe.ps1` runs only from the owner-launched A2 harness as the actual local `AclaisWorker` identity. It exercises disposable `C:\ACLAIS-Lab` fixtures plus read/write denials against checkout application source and a synthetic evidence marker. It records Windows errors and creates no production service or tool.

The current demonstration-machine result is recorded in [`../../evidence/A2.md`](../../evidence/A2.md). Portable CI does not run or prove these Windows ACL checks.
