# Defensive scope

The tool checks expected DNS/IP names against a user-supplied local certificate
to help review service-name configuration. It requires no credentials, network
target, remote certificate retrieval, private key, or live application access.
It creates no sockets, performs no DNS lookup, initiates no handshake, and sends
no telemetry. Runtime effects are bounded local reads and a JSON stdout report.
CI/build dependency installation has its ordinary package-download behavior.

Only DNS and IP SAN name checks are implemented. URI/SRV and other SAN identity
types are explicitly reported as ignored or unsupported. The tool does not
build or validate a certificate chain, verify a signature, enforce validity
dates, query revocation, check a public suffix, test service reachability, or
authenticate a person or organization. `trust_status` is always `OPEN`.

`PASS` refers only to a supported name match; `FAIL` means a supported reference
has no matching SAN. Parsing, path, bounds, malformed SAN, unsupported-only SAN,
and unsupported-reference results are `OPEN`. Invalid SANs cannot produce a
match. No CN fallback exists. See README for policy differences and all limits.

Synthetic public certificates under examples use `.test` and documentation
addresses. Tests generate temporary signing keys only in memory; no private key
is serialized, included, or needed for evaluation. Reports do not dump
certificate subjects, private material, or untrusted parser errors.

This is a defensive project candidate for a portfolio. Applicant eligibility,
legal identity, organizational affiliation, real model guardrail obstacles, and
CVP review are external matters and remain `OPEN`. The project makes no promise
of admission or absence of model-policy intervention.
