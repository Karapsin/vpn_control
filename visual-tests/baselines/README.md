# Visual Baselines

Canonical PNG baselines are tracked through Git LFS under one directory per platform:

```text
visual-tests/baselines/android/
visual-tests/baselines/linux/
visual-tests/baselines/windows/
visual-tests/baselines/macos/
```

The first complete baseline set is recorded by the coding agent from the matching isolated local environment. Eligible non-secure scenes may use an agent-dispatched ephemeral hosted VM. A release verification run never creates or updates baselines. See `agent_docs/visual-regression.md`.
