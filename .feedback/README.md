# Feedback task starting environment

Upstream: https://github.com/ronf/asyncssh
Upstream commit: `f1d1c7505468e3ebfd4eda90d831934e20f69bdf`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m unittest -q tests.test_packet tests.test_known_hosts tests.test_auth_keys tests.test_sshsig
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `OK (skipped=5)`
Whole-command wall time: 1.198 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
