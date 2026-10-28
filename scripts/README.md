# Repository-wide orchestration

This folder contains commands that coordinate implemented component checks from the repository root. `check.ps1` currently delegates to ACLAIS portable checks because ACLAIS is the only implemented production component. It resolves the repository path from its own location and works from any caller working directory.

Add a component's real checks here only when its prerequisite gate passes and implementation exists. Do not add placeholder success steps. Component-specific setup, test, or deployment commands stay with that component, such as `aclais/scripts/`.
