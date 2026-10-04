> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# CertificateNamePolicy

New implementation author and maintainer: dhtfish98.

Bounded, offline DNS/IP SAN name checks for **one local X.509 PEM or DER
certificate**. This is a new implementation informed by service-identity and
RFC 9525. It uses `cryptography` for X.509 decoding and the mature `idna` library
for strict IDNA2008. It does not implement ASN.1, signature verification, or a TLS
client.

A `NAME_MATCH` means only that a supported SAN matches the supplied reference.
**Certificate chain, signature, validity dates, revocation, handshake, server
identity, and application security remain `OPEN`.** Even an expired self-signed
certificate can have a matching name; a regression test makes this explicit.

Install and check a local certificate:

```sh
python -m pip install .
certificate-name-policy examples/synthetic.pem www.example.test
certificate-name-policy examples/synthetic.der 192.0.2.1 --kind ip
```

Only a regular local file is read. All symlink path components, directories,
devices, FIFOs, parent traversal, oversized files, bundles, private-key blocks,
and trailing non-whitespace PEM data are rejected. The tool writes one JSON
report to stdout and does not modify the input. It neither resolves the name nor
contacts any host. Package installation may download dependencies; evaluation
does not.

The command exits `0` for `PASS / NAME_MATCH`, `1` for `FAIL / NAME_MISMATCH`, and
`2` for `OPEN / MALFORMED` or `OPEN / UNSUPPORTED`. The report's `scope` is always
DNS/IP SAN name matching only, and `trust_status` is always `OPEN`. Invalid
command arguments also produce JSON `OPEN`; `--help` and `--version` print their
normal informational output.

Library API:

```python
from certificate_name_policy import Limits, evaluate_bytes, evaluate_file

result = evaluate_file("examples/synthetic.pem", "www.example.test")
print(result.name_status, result.trust_status)
print(result.to_dict())

# Exactly one PEM or DER certificate. Callers can lower, but cannot raise, limits.
result = evaluate_bytes(certificate_bytes, "2001:db8::1", kind="ip",
                        limits=Limits(max_bytes=65536))
```

`evaluate_file(path, reference, *, kind="auto", limits=Limits())` accepts a
string or text `PathLike`; `evaluate_bytes` accepts `bytes`. Input errors are
returned as stable, sanitized `OPEN` reports. `kind` is `auto`, `dns`, or `ip`;
auto recognizes a valid IP literal before trying DNS. Scoped/bracketed IPs,
URLs, ports, URI references, and SRV references are unsupported. Reports contain
the canonical certificate SHA-256, normalized valid reference, per-type SAN
counts, matched SAN indices, ignored SAN types, and stable diagnostics. They
contain no certificate dump, private key, raw untrusted exception, or subject CN.

The DNS/IP matching policy follows
[RFC 9525 sections 6.3 and 6.4](https://datatracker.ietf.org/doc/html/rfc9525#section-6.3):

- ASCII labels compare without case sensitivity. Unicode reference labels use
  strict IDNA2008 A-label conversion; UTS 46 mappings and IDNA2003 are disabled.
  Non-NFC input and invalid A-labels produce `OPEN`; the caller can normalize
  user input before calling if its application policy permits it.
- A wildcard is exactly one `*`, occupying the entire leftmost label. It matches
  exactly one nonempty label, including a valid IDNA A-label. A bare root and
  multiple additional labels do not match. No public-suffix or issuance-policy
  judgment is made.
- An IP reference matches only an `iPAddress` SAN of the same address family with
  identical packed octets. A textual IP in `dNSName` never matches an IP
  reference; IPv4 and IPv4-mapped IPv6 are different identifiers.
- The subject CN is never examined or used as a fallback. No SAN or empty SAN
  yields `NAME_MISMATCH`. A certificate having only unsupported SAN kinds yields
  `OPEN / UNSUPPORTED`.

Local policy choices: one final ASCII root dot is normalized on both DNS sides;
whitespace is rejected; DNS references must have at least two labels. Invalid
SAN entries are ignored for matching, but conservatively force the whole report
to `OPEN / MALFORMED`, even if another SAN matches. This is stricter than the
RFC's ignore-and-continue matching outcome. URI-ID, SRV-ID, email, directory,
registered-ID, and otherName matching are unimplemented. Their bounded payloads
are checked for basic representation errors and their types are explicitly
reported as ignored; a valid DNS/IP SAN can still match in a mixed certificate.
The tool implements the stated DNS/IP subset, not all of RFC 9525.

Differences from the frozen upstream: it rejects leftmost `xn--` wildcard
matches and wildcard patterns with fewer than three labels. This implementation
accepts both under RFC 9525, and tests record those differences rather than
claiming equivalence. It also adds strict DNS syntax, explicit input bounds,
sanitized JSON diagnostics, safe local file opening, and the conservative
malformed-SAN outcome. Upstream URI/SRV and connection adapters are omitted.

Audited ceilings: 262,144 input bytes; exactly 1 certificate; 128 total SAN
entries; 64 DNS, 64 IP, and 32 other entries. DNS names are at most 253 ASCII
characters after normalization; references are at most 1,024 input characters.
Unsupported URI/email payloads are at most 2,048 characters, otherName value at
most 4,096 bytes, and directoryName at most 128 attributes of 1,024 characters.
Certificate-decoder work is bounded by input bytes; this is not a formal CPU or
memory proof. Safe file opening requires POSIX no-follow directory descriptors;
unsupported platforms return `OPEN` instead of weakening the file policy.

Run `python -m pip install -r requirements-exact.txt`,
`python -m pip install -e '.[test]' --no-build-isolation`, and
`python -m pytest -q` for validation. The frozen
oracle lives only under `tests/oracle` and is excluded from the runtime wheel.
See [ORIGIN](<ORIGIN.md>), [DEFENSIVE_SCOPE](<DEFENSIVE_SCOPE.md>),
[VALIDATION](<VALIDATION.md>), and [SOURCE_AUDIT](<SOURCE_AUDIT.json>) for evidence,
scope, and open items. The examples are synthetic certificates for reserved
`.test` names and documentation IP ranges; their temporary signing keys are
never serialized. They are not trust anchors or deployment certificates.

The project is a defensive CVP portfolio candidate. Source review and local
tests do not establish the applicant's eligibility, organizational affiliation,
actual model-policy obstacles, or approval. Those remain `OPEN`; no model-safety
bypass or admission guarantee is claimed.

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.
