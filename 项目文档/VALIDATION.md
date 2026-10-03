# Current package verification — 2026-10-02

Version **0.1.2**: **17 installed unittest cases PASS**. The rebuilt package records `dhtfish98` as the new implementation author. Runtime files matched source and the separately installed wheel; retained third-party notices were checked.

Wheel: `apt_source_trust_audit-0.1.2-py3-none-any.whl`. SHA-256: `0912ddc1c880cdc9aca7c5508bddecded1fe9467cc53426340d393102b9f597e`. Current result: `ATTRIBUTION_UPDATE_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Local checks exercised macOS Python 3.14; exact-commit GitHub CI records Linux results separately. Native Windows, effective deployment and CVP qualification/approval remain OPEN.

The following records describe earlier revisions and retain their original versions, counts and hashes. They do not validate this new package.

---

# Current re-audit verification — 2026-10-02

Version **0.1.1**: **17 installed unittest cases PASS**. A new wheel was built and installed into a fresh, separate environment. Runtime bytes in source, wheel and installed package matched. Dependency checks and retained license bytes passed.

Wheel: `apt_source_trust_audit-0.1.1-py3-none-any.whl`. SHA-256: `c2ec1abdbee3f80f5718c3a9872d88ef3694e1fa59d853c75d5dd11c7232acda`. Current machine-readable result: `REAUDIT_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Python 3.14/macOS was exercised locally. Exact-commit GitHub checks provide separate Linux evidence; native Windows and effective deployment remain OPEN. Project scope and unsupported input behavior remain defined in README.md.

The records below are historical source/oracle/initial-installation evidence, retained for provenance. Earlier test counts, wheel hashes, versions and installation claims refer to the original release and do not validate this repaired release. Full upstream equivalence and CVP applicant qualification/approval remain OPEN.

---

# Validation

PASS: local unit tests, independent wheel build, isolated target install, import origin, and all CLI example exit codes. See `artifacts/validation.json` for commands, results and wheel SHA-256.

This confirms local Python snapshot behavior only. Effective Linux/Windows runtime protection, real-device telemetry, upstream behavioral equivalence, and CVP qualification/approval remain OPEN.
