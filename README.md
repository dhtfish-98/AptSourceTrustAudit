# AptSourceTrustAudit

Version **0.1.2**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

APT source format and repository trust configuration audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"files":{"/etc/apt/sources.list":"deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://packages.example.invalid stable main"},"global_options":{},"global_options_complete":true}`. Both one-line `.list` and multiline/multivalue Deb822 `.sources` are parsed. Enabled:no stanzas are explicitly outside active-source scope. Checks cover required fields/types/components/exact-path suites, duplicate fields/options/repositories, bounded URI/suite/type expansion, scoped signing declarations, insecure/weak/downgrade/trusted overrides, expiry/date/HTTPS verification overrides, transport scheme, embedded credentials, query/fragment scope and unknown settings. Signed-By is only a path/fingerprint declaration: no key file is opened, cryptographic trust checked or network contacted. Embedded keys/fingerprint-only global trust/nonstandard key paths are OPEN. HTTPS is a project transport policy; HTTP still may retain valid APT signature verification. Missing caller assertion of global completeness is OPEN. Repository URIs containing credentials are not echoed in findings.

## Use and output

Install `artifacts/*.whl` and run `apt-source-trust-audit examples/good.json`, or `python -m apt_source_trust_audit examples/good.json`. JSON findings have PASS/FAIL/OPEN, evidence, explanation and counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Incomplete/unsupported evidence cannot produce exit 0. Input: regular non-symlink unchanged file, 2 MiB maximum, 32 JSON layers, 100000 nodes, no duplicate keys/nonfinite values; findings cap 20000. Each project is independently packaged with no external runtime dependency.

## Verification and limits

Read `ORIGIN.md`, `NOTICE` where present, `tests/`, `examples/expectations.json`, `VALIDATION.md` and exact `artifacts/validation.json`. Tests use public frozen policy data or synthetic fixtures only. Local parser/policy/wheel/CLI results are separate from real Linux/Windows execution, effective security, upstream equivalence and CVP eligibility/approval, which remain OPEN. No live host collection, code execution, configuration change or network action occurs.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.
