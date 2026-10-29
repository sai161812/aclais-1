# Repository-wide orchestration

This folder contains commands that coordinate implemented components from the repository root. `check.ps1` delegates to ACLAIS portable checks. `start.ps1 -Service Backend` and `start.ps1 -Service Frontend` delegate to the ACLAIS foreground development servers; run one per terminal and stop each with Ctrl+C. Both commands resolve component paths from their own location and work from any caller working directory. ACLAIS is the only implemented production component.

Add a component's real checks here only when its prerequisite gate passes and implementation exists. Do not add placeholder success steps. Component-specific setup, test, or deployment commands stay with that component, such as `aclais/scripts/`.

`aclais.ps1 -Action start|stop|doctor|reset|teardown` delegates protected owner operations. Start stays in the foreground. Stop checks the recorded owner process creation identity and requests orderly shutdown. Reset requires an idle owned installation. Teardown requires the exact root ID and archives the runtime; consult RUNBOOK.md before removal.
