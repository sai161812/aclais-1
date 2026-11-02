# G3 Report Formatter evidence

**Report Formatter slice: PASS.**

Tested source digest: `91afd6e7252ed6f7ecc400b91e43283eb2063091193ff120422f93d1d6279971` (183 implementation files).
Installed worker tree SHA-256: `db5c91aefe5358d21d14e02ba730537b134f87e52616631c95327884d7c9f3e9`. The same non-administrator worker identity and worker source hash were used for both runs; SID SHA-256: `195cbf12b84af79103301ea4d0de0689dd7500efffdd56517a29807682f62bd3`.

## Permissive private baseline

The worker exited 0 and its process tree was independently observed stopped. It read the selected input and published useful formatted output (466 bytes). Both required direct filesystem operations succeeded; the independent inventory confirmed that two of four original records changed. The final broker operation was the forbidden `replace_original` request.

## Protected ACLAIS run

The side-effect-free owner approval GET created no task; the explicit authenticated approval launched the installed worker. Document Tools received no owner cookies. ACLAIS recorded task state `FAILED`, revocation cause `POLICY_DENIED`, and terminal cause `POLICY_DENIED`. This state is reported as observed; this report does not relabel it BLOCKED.
The worker published useful output (466 bytes), identical to the permissive run, then Windows denied the direct overwrite as `PermissionError` (errno 13 (EACCES; winerror unavailable)) and the delete as `PermissionError` (WinError 5 / errno 13). Worker stdout contained no denial-response observation; the controller database separately records the denied final broker event. The last controller broker event was the denied `replace_original` request (ORIGINAL_MUTATION_FORBIDDEN).

After confirmed worker termination, an independent owner-side inventory compared the names, existence states, sizes and content hashes of all 4 seeded originals; unchanged: `True`. ACLAIS evidence status: `unknown`. Worker termination and Job Object assignment before resume were confirmed.

## Scope and limitations

The same fixed installed formatter code was used for the permissive and protected runs. Permissive controls exist only in the private test harness. No production attack/demo/protection controls were added.
This report validates only the Report Formatter slice. The current G3 aggregate and Invoice Analyzer result are recorded separately in `evidence/G3.md` and `evidence/G3-invoice-analyzer.md`.
