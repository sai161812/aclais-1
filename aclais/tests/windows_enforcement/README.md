# Windows enforcement checks

This lane contains automated checks that use real Windows identities, NTFS access controls, Windows Credential Manager, and Job Objects. A2 and A3 demonstration-machine results are recorded in [`../../../evidence/A2.md`](../../../evidence/A2.md) and [`../../../evidence/A3.md`](../../../evidence/A3.md). The automated checks must run on the demonstration machine; portable CI does not prove Windows enforcement. Do not replace a required Windows check with a mock or mark an absent/skipped test as passed.
