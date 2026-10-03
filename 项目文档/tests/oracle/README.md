Frozen test-only oracle: pyca/service-identity commit
`5d0a376d74042920edf3dd03942602b52cb100c8`.

These five original runtime files and `py.typed` are copied unchanged from the
fixed source snapshot. SOURCE_AUDIT.json records their hashes. The complete
original MIT license is preserved in THIRD_PARTY_LICENSES/service-identity-MIT.txt.

They are never imported by CertificateNamePolicy runtime, never packaged in its
wheel, and never used as its implementation. Tests compare supported DNS/IP
behavior using real, locally generated synthetic X.509 certificates. URI/SRV,
malformed patterns, root-dot/whitespace handling, and wildcard A-label policy
are outside the equivalence domain; explicit difference tests cover the latter.
