# Validation

Local evidence dated 2026-10-02 (Asia/Tokyo), Python 3.14.6 on macOS 26.7 arm64.
Runtime versions: cryptography 47.0.0, idna 3.20, cffi 2.1.1, pycparser 3.0.
The local test run reported **165 passed, 0 failed, 0 skipped**. This is local
automated evidence, not deployment, certificate-trust, or CVP-eligibility proof.

| Check | Observed result |
| --- | --- |
| All five frozen upstream runtime files read and attributed | PASS; SOURCE_AUDIT.json records roles and hashes |
| New runtime, CLI, tests, packaging scripts/config, and CI source review | PASS within stated scope; no formal security audit claimed |
| Name policy and input/resource boundary regression tests | PASS; 165 tests total |
| Frozen original DNS/IP differential support domain | PASS; 18 DNS and 5 IP cases |
| Explicit RFC 9525 wildcard behavior differences | PASS; 2 cases assert new outcome differs from original |
| Frozen original source and complete license hashes | PASS; verified by tests |
| Lint, formatting, and installed dependency consistency | PASS |
| Wheel and sdist build | PASS; version 0.1.0 |
| Metadata name/version/Python/dependency pins/CLI entry point | PASS |
| Complete new and upstream MIT licenses in wheel and sdist | PASS; exact content compared to source |
| Wheel RECORD integrity | PASS; 11 non-RECORD files checked |
| Test oracle absent from runtime wheel | PASS |
| Fresh wheel installation with no index, using local dependency wheels | PASS |
| Installed command line match/mismatch/invalid-reference/missing-file cases | PASS; 5 cases returned expected exit codes and JSON |
| Installed runtime with socket audit events blocked | PASS; DNS/IP name check made no socket event |
| Remote CI workflow | OPEN; checked in, not remotely executed here |

Independent examples and tests use real synthetic X.509 certificates, not SAN
JSON surrogates. Covered cases include PEM/DER, CN-only and empty SAN, strict
IDNA2008, A-label/U-label comparisons, root-dot policy, exact wildcard label
depth, partial/multiple wildcards, IPv4/IPv6 and mapped-address separation,
DNS-text IP type confusion, duplicate SANs, unsupported SAN types, NUL/control
characters, invalid IA5 octets, unknown GeneralName tag, duplicate extensions,
IP SAN length errors, bundles/trailing data/private-key blocks, per-type/total
SAN limits, exact byte-limit boundaries, symlink leaf/parent, traversal,
FIFO/device/directory input, growing/changing files, and sanitized exceptions.
An expired self-signed certificate and a corrupted signature can match a name;
those tests require `trust_status=OPEN`, preventing a name-only result from
claiming trust verification.

The new source review checked runtime imports and effects, parser-error paths,
bounded loops and output, descriptor cleanup, no-follow opens, no CN access,
name-type dispatch, IDNA flags, label matching, CLI exit/JSON behavior, ephemeral
test keys, test-only oracle imports, package inclusion rules, entry point,
license preservation, CI permissions/pinned actions, and verification scripts.
The two pinned GitHub action commit manifests were reachable at their official
raw source URLs. Reading this source is not a vulnerability scan of transitive
dependencies or a full line-by-line audit of the upstream tests/docs/CI.

Reproduce from a source checkout:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-exact.txt
.venv/bin/python -m pip install -e '.[test]' --no-build-isolation
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts --exclude tests/oracle
.venv/bin/ruff format --check src tests scripts --exclude tests/oracle
.venv/bin/python -m pip check
.venv/bin/python -m build --no-isolation
.venv/bin/python scripts/verify_package.py dist/*.whl dist/*.tar.gz
python -m venv .install-check
.install-check/bin/python -m pip install dist/*.whl
.install-check/bin/certificate-name-policy examples/synthetic.pem www.example.test
.install-check/bin/python scripts/offline_smoke.py examples/synthetic.der 192.0.2.1 --kind ip
```

Local wheel/sdist SHA-256 and downloaded dependency wheel hashes were recorded
in the separate engineering evidence. Rebuilds can have different archive
timestamps and hashes; run the verifier on the exact artifacts being reviewed.
Installation can download pinned dependencies; evaluation is offline. The
local fresh-install check additionally used `--no-index` and local wheels.

Known open items: remote CI has not run; other OS/Python versions, dependency
security audit, real deployment integration, certificate trust verification,
URI/SRV matching, actual model-policy obstacles, applicant eligibility, and CVP
approval have not been validated. Tests and build success do not prove any of
those outcomes.
