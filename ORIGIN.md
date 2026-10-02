# Origin and attribution

Design source: [pyca/service-identity](https://github.com/pyca/service-identity),
frozen commit `5d0a376d74042920edf3dd03942602b52cb100c8` (candidate snapshot dated
2026-10-01). The complete original MIT license and Hynek Schlawack/contributor
copyright are retained unchanged in
`THIRD_PARTY_LICENSES/service-identity-MIT.txt` and included in distributions.
The new implementation is MIT licensed under `LICENSE`.

All five source runtime files were read: `__init__.py`, `exceptions.py`,
`cryptography.py`, `hazmat.py`, and `pyopenssl.py`. SOURCE_AUDIT.json records the
exact snapshot paths, hashes, pinned URLs, and review findings. No original
runtime implementation is imported or copied into the new runtime. Its X.509
adapter, IDNA validation, label matcher, report contract, path reader, and CLI
were written independently. `tests/oracle/service_identity` retains those five
files and `py.typed` verbatim solely for differential testing, under the original
MIT license. They are excluded from the wheel and not an application API.

The differential support domain is syntactically valid, fully qualified DNS
names, fixed exact A-label/U-label identities, conventional three-or-more-label
wildcards without an internationalized first reference label, and exact IP
SANs. Tests assert the expected outcome independently as well as comparing to
the frozen original. Two other tests explicitly assert the new RFC 9525
wildcard outcomes differ from upstream. No equivalence claim covers malformed
inputs, whitespace, root dots, URI/SRV, optional/obligatory multi-ID matching,
connection APIs, bounds, or trust validation.

Normative matching source:
[RFC 9525, sections 6.3 and 6.4](https://datatracker.ietf.org/doc/html/rfc9525#section-6.3),
read on 2026-10-02. The local DNS/IP subset and stricter behavior are documented
in README. `cryptography==47.0.0` and `idna==3.20` are the pinned runtime
dependencies exercised here; their own licenses remain with those separately
installed third-party distributions. Exact validation versions are recorded in
requirements-exact.txt. No dependency vulnerability or formal security audit is
claimed.
