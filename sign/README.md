# `sign` — digital signature schemes

This package tree provides the digital signature primitives and the **hybrid signature schemes**
used by [QuantumCoin](https://quantumcoin.org) to sign and verify transactions, blocks and
consensus messages.

## Intended Scope — Important

🔒 **This package is purpose-built for QuantumCoin blockchain software and is not offered as a
general-purpose cryptographic library.**

It is supported only for building and operating QuantumCoin nodes, wallets, dApps and tooling.
Using the hybrid schemes — or the WASM bindings that expose them — as a general signing library
is **unsupported**, and the security analysis in [`../audit/`](../audit) does not extend to that
use.

This matters more here than in most packages, because the hybrid schemes deliberately rely on
properties that the library does **not** itself enforce. They hold in QuantumCoin software; they
are not guaranteed for an arbitrary caller. In particular:

| The schemes assume the caller… | Consequence if violated |
|---|---|
| derives identity from a hash of the **complete** composite public key, never a component or prefix | a component signature can be transplanted into a different composite key ([FINDING-001](../audit/FINDING-001-key-substitution.md)) |
| passes messages of **exactly** 32 bytes | mode separation in `hybrideds` rests on a payload-length asymmetry ([FINDING-002](../audit/FINDING-002-cross-mode-separation.md)) |
| supplies randomness from a **CSPRNG**, never `nil` and never a short-reading reader | silently degraded hedging randomness; a `nil` reader panics |
| supplies base seeds that are **uniformly random across every byte position** | the legacy `hybrideds` expander reads only 64 of its 96 input bytes ([FINDING-000](../audit/FINDING-000-seed-expander-entropy.md)) |
| pins an acceptable **scheme ID per account** | compact and full signatures become fungible, and compact carries no hash-based protection ([FINDING-008](../SECURITY_AUDIT.md#finding-008)) |
| never reuses a component key outside the hybrid | the Ed25519 component is a valid standalone RFC 8032 signature over the message |

The [audit index](../SECURITY_AUDIT.md) states each of these explicitly and records whether it
currently holds in each known consumer.

## Standards status

- **Schemes 3–5** (`hybridedmldsaslhdsa`, `hybridedmldsaslhdsa5`) use the finalized NIST
  algorithms: ML-DSA ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)), SLH-DSA
  ([FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)) and Ed25519
  ([FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5) §7.8). **Prefer these for new designs.**
- **Schemes 1–2** (`hybrideds`) realize the pre-standardization Round 3 drafts —
  [Dilithium2](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
  and [SPHINCS+-SHAKE-256f-simple](https://sphincs.org/data/sphincs+-r3.1-specification.pdf) —
  reached through the `Internal` / `NoContext` entry points of the FIPS-era implementations. They
  are retained for wallet backward compatibility. Cross-checking them against FIPS 204 / FIPS 205
  test vectors will produce a false mismatch.
- **No FIPS conformance or CMVP validation is claimed** for any scheme in this tree.

## Packages

| Package | Contents |
|---|---|
| [`ed25519`](./ed25519) | Ed25519 / Ed25519ctx / Ed25519ph (RFC 8032) |
| [`mldsa`](./mldsa) | ML-DSA-44 / 65 / 87 (FIPS 204) |
| [`slhdsa`](./slhdsa) | SLH-DSA, twelve parameter sets, pure and pre-hash (FIPS 205) |
| [`hybrideds`](./hybrideds) | Scheme IDs 1–2 — legacy hybrid (Ed25519 + Dilithium2 + SPHINCS+) |
| [`hybridedmldsaslhdsa`](./hybridedmldsaslhdsa) | Scheme IDs 3–4 — Ed25519 + ML-DSA-44 + SLH-DSA-SHAKE-256f |
| [`hybridedmldsaslhdsa5`](./hybridedmldsaslhdsa5) | Scheme ID 5 — Ed25519 + ML-DSA-87 + SLH-DSA-SHAKE-256s (NIST Level 5) |
| [`hybridparser`](./hybridparser) | **Audit tooling only** — decomposes hybrid signatures for independent per-component verification. Not for production verification. |
| [`schemes`](./schemes) | Scheme registry (hybrid schemes are intentionally absent) |
| [`wasm`](./wasm) | JavaScript/WASM bindings for the hybrid schemes |

## Testing

The hybrid packages contain exhaustive bit-flip tests that exceed Go's default 10-minute test
timeout. Run them with an explicit timeout:

```sh
go test -timeout 45m ./sign/...
```

Without it, `sign/hybridedmldsaslhdsa` reports a spurious failure that is a timeout, not a
correctness problem.

## Security

Findings, severities and per-consumer applicability are recorded in
[`../SECURITY_AUDIT.md`](../SECURITY_AUDIT.md). Report security issues through the repository
[Security Policy](https://github.com/quantumcoinproject/circl/security/policy).
