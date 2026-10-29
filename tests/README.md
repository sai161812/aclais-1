# Cross-component tests

Root `tests/` is reserved for integration and acceptance checks that exercise the specified interfaces between multiple components. Keep component tests, private probes, fixture templates, and component-only test support in their owning component folders (`aclais/tests/`, `receiver/tests/`, and `document-tools/tests/`). There are no cross-component integration tests until their component prerequisites pass.
