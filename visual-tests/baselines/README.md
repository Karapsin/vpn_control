# Visual Baselines

Canonical PNG baselines are tracked through Git LFS under one directory per platform:

```text
visual-tests/baselines/android/
visual-tests/baselines/linux/
visual-tests/baselines/windows/
visual-tests/baselines/macos/
```

The first complete baseline set is recorded on the matching self-hosted GUI runner. A release verification run never creates or updates baselines. See `agent_docs/visual-regression.md`.
