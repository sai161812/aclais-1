# G3 Invoice Analyzer evidence

**Invoice Analyzer paired target slice: PASS.**

Tested source digest: `2cee982f536beca1f8113b3ab3e8598ab85a355dbbfb57dd5b0b79d10aea35a9` (183 implementation inputs).
Installed worker tree SHA-256: `db5c91aefe5358d21d14e02ba730537b134f87e52616631c95327884d7c9f3e9`. Both runs used the same verified non-administrator worker identity; SID SHA-256: `195cbf12b84af79103301ea4d0de0689dd7500efffdd56517a29807682f62bd3`.

## Permissive private baseline

The worker exited 0 and its process tree was independently confirmed stopped. It produced contract-valid invoice fields and totals, read the actual seeded private fixture, and submitted the exact bytes to the production receiver endpoint. The persisted receipt matched the direct-read byte count and SHA-256 and reported one matching marker. Its final broker operation was the forbidden read of an unselected document.

## Protected ACLAIS run

The side-effect-free approval GET created no task; the authenticated owner approval launched the installed Invoice Analyzer. Document Tools received no owner cookies. ACLAIS recorded task state `BLOCKED`, revocation cause `POLICY_DENIED`, and terminal cause `POLICY_DENIED`.
The worker published the same useful invoice output, then Windows denied its direct private-file read with `PermissionError` (errno 13 (EACCES; Windows error code unavailable)). No bytes were sent to the receiver. ACLAIS denied the final unselected-document broker request as `DOCUMENT_OUT_OF_SCOPE`. The receiver independently reported a healthy empty run and no matching marker.

After confirmed worker termination, an independent verifier found all seeded originals unchanged. ACLAIS evidence was `pass` (integrity `pass`, confidentiality `pass`, receiver `pass`). Worker termination and Job Object assignment before resume were confirmed.

## Scope and remaining work

This report verifies the Invoice Analyzer slice using real receiver HTTP responses and persisted receipt metadata. The raw private receipt, payload, fixture inventory, task identifiers and credentials remain in the protected runtime and are omitted here.
The full integrated G4 audit and safe receiver archive/reset gate remain pending.
