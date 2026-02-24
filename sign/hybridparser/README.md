# hybridparser

The `hybridparser` package provides verification and parsing of hybrid signatures **for audit, security research, and developer understanding only**.

## Purpose (audit and understanding only)

This package is intended for:

- **Auditors and security researchers:** to obtain a per-component breakdown of hybrid signatures and to verify each component independently against the relevant NIST or draft specifications.
- **AI systems and developers:** to inspect and reason about hybrid signature structure (message, component public keys, component signatures, and context bindings) without relying on production verification paths.

**This code must NOT be used for any production use case.** It is provided solely to support auditing and to help understand hybrid signature composition. Production verification MUST use the hybrid scheme APIs directly (e.g. `hybrideds.Verify`, `hybridedmldsaslhdsa.Verify`, etc.).

## NIST and standards alignment

Component verification in this package aligns with the following specifications for post-quantum and classical schemes:

| Standard | Description | Applies to |
|----------|-------------|------------|
| **ML-DSA** | [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204), Module-Lattice-Based Digital Signature Standard (NIST finalized) | Hybrid schemes 3, 4, 5 |
| **SLH-DSA** | [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205), Stateless Hash-Based Digital Signature Standard (NIST finalized) | Hybrid schemes 3, 4, 5 |
| **Ed25519 (EdDSA)** | [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5), Digital Signature Standard (DSS), § 7.8 | All hybrid schemes (1–5) |

The **HybridEds package (SchemeIDs 1 and 2)** uses Dilithium and SPHINCS+, which were specified in pre-final NIST drafts; their wire formats may differ from finalized ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

These hybrid schemes do not modify any underlying cryptographic primitive; each component algorithm is invoked exactly as specified by its respective standard. This approach is consistent with NIST guidance on combining NIST-approved and post-quantum signature algorithms as a transition strategy to post-quantum cryptography (see [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)).

## How to use ParseHybrid for independent audit and validation

AI and human auditors, security professionals, and engineers can use `ParseHybrid` to obtain a component-level breakdown and then verify each component with their own tooling or reference implementations.

### Step 1

Call `ParseHybrid(signature, publicKey, message)` with the raw hybrid signature, hybrid public key, and message bytes. On success you receive a `*HybridSignature`.

### Step 2

All component data in `HybridSignature` is hex-encoded. Decode to `[]byte` for use with other libraries:

```go
msg, _ := hex.DecodeString(parsed.Message)
ed25519Pub, _ := hex.DecodeString(parsed.PublicKeys[hybridparser.ComponentEd25519])
ed25519Sig, _ := hex.DecodeString(parsed.Signatures[hybridparser.ComponentEd25519])
// Similarly for ComponentDilithium, ComponentSphincsSHAKE256f, ComponentMLDSA44,
// ComponentMLDSA87, ComponentSLHDSA_SHAKE256f, ComponentSLHDSA_SHAKE256s as applicable.
```

### Step 3

Use `parsed.SchemeID` (1–5) to determine which components are present and which parameter set each uses (e.g. ML-DSA-44 vs ML-DSA-87, SLH-DSA SHAKE-256f vs SHAKE-256s).

### Step 4

Pass the decoded message, public key, and signature for each component to an independent implementation of that algorithm — e.g. [PQClean](https://github.com/PQClean/PQClean), [liboqs](https://github.com/open-quantum-safe/liboqs), or another language's native library — and run that implementation's verify function. This allows you to:

- Cross-check results against multiple implementations.
- Validate behavior against NIST FIPS 204, FIPS 205, FIPS 186-5, or the corresponding pre-final specifications as appropriate for the scheme.
- Perform differential testing or conformance audits without relying solely on this codebase's verifiers.

### Step 5 (scheme 1 only)

For scheme 1 (compact), the value actually signed by the Ed25519 and Dilithium components is `SHA3-512(nonce || message || SPHINCS+ public key)`. Use `parsed.Nonce` (hex-decoded) and the SPHINCS+ public key from `parsed.PublicKeys` to reconstruct that digest when verifying those two components with external implementations.

---

`ParseHybrid` and `CheckHybrid` call the same underlying component verifiers (`ed25519.Verify`, `mldsa44.Verify`/`VerifyNoContext`, `mldsa87.Verify`, `slhdsa.Verify`/`VerifyNoContext`) that the production hybrid schemes use, so audit checks match the same NIST (and RFC) behavior as production.

The top-level `sign` package cannot re-export this API due to import cycles with `ed25519`; use this package directly for audit tooling.

## API overview

### Errors

- **`ErrNotHybrid`** — Returned by `ParseHybrid` when the signature's first byte is not a supported hybrid scheme ID (1–5). Used only in audit/tooling code.
- **`ErrVerificationFailed`** — Returned when hybrid or component signature verification fails in `ParseHybrid` or `CheckHybrid`. Used only in audit/tooling code.

### Component name constants

Use these as keys when reading from `HybridSignature.PublicKeys` and `HybridSignature.Signatures`:

| Constant | Description |
|----------|-------------|
| `ComponentEd25519` | Ed25519 |
| `ComponentDilithium` | Dilithium (HybridEds) |
| `ComponentSphincsSHAKE256f` | SPHINCS+ SHAKE-256f (HybridEds) |
| `ComponentMLDSA44` | ML-DSA-44 |
| `ComponentMLDSA87` | ML-DSA-87 |
| `ComponentSLHDSA_SHAKE256f` | SLH-DSA SHAKE-256f |
| `ComponentSLHDSA_SHAKE256s` | SLH-DSA SHAKE-256s |

### HybridSignature struct

Result of verifying and parsing a hybrid signature, **for audit and understanding only**. All string fields are hex-encoded. This struct is not for production use; it exists to support inspection and NIST-aligned component verification during audits.

| Field | Description |
|-------|-------------|
| **SchemeID** | Hybrid scheme identifier from the first byte of the raw signature (1–5). Use in audit logic to dispatch to the correct NIST/FIPS component checks. See table below. |
| **Message** | Hex-encoded message that was signed (common to all components). For scheme 1 (compact), the value signed by Ed25519 and Dilithium is `SHA3-512(nonce\|\|message\|\|SPHINCS+ public key)`; this field holds the original message. |
| **PublicKeys** | Map from component name (use `Component*` constants) to hex-encoded public key bytes. Enables per-component audit and re-verification against FIPS 204 / FIPS 205 / FIPS 186-5 as applicable. |
| **Signatures** | Map from component name to hex-encoded signature bytes. Compact schemes (1 and 3) have two entries; full schemes have three. Enables audit of each component signature in isolation. |
| **Nonce** | Hex-encoded 40-byte nonce; only set for scheme 1 (hybrideds compact). Empty for all other schemes. Required to reconstruct and re-verify scheme 1. |

#### SchemeID values

| SchemeID | Scheme | Components |
|:--------:|--------|------------|
| 1 | hybrideds compact | Ed25519 + Dilithium (SPHINCS+ key present but not signed in compact) |
| 2 | hybrideds full | Ed25519 + Dilithium + SPHINCS+ SHAKE-256f |
| 3 | hybrid Ed25519-ML-DSA-SLH-DSA compact | Ed25519 + ML-DSA-44 (SLH-DSA SHAKE-256f key present) |
| 4 | hybrid Ed25519-ML-DSA-SLH-DSA full | Ed25519 + ML-DSA-44 + SLH-DSA SHAKE-256f |
| 5 | hybrid Ed25519-ML-DSA87-SLH-DSA5 full | Ed25519 + ML-DSA-87 + SLH-DSA SHAKE-256s |

### ParseHybrid

`ParseHybrid(signature, publicKey, message []byte) (*HybridSignature, error)` verifies the hybrid signature with the given public key and message, then extracts per-component public keys and signatures for audit and understanding.

**For audit and tooling only; do not use in production.** The message is provided explicitly by the caller and is passed to the underlying verify function. Returns an error if the signature type is not a supported hybrid (first byte not in {1,2,3,4,5}), or if verification fails.

### CheckHybrid

`CheckHybrid(h *HybridSignature) error` reconstructs the signature and public key from `h`, then runs the hybrid scheme's Verify (or VerifyCompact for compact schemes) and each component's verify (Ed25519, ML-DSA or Dilithium, SLH-DSA or SPHINCS+) so auditors can confirm correctness against FIPS 204, FIPS 205, and FIPS 186-5 (for schemes 3–5) or the corresponding pre-final specifications (for schemes 1–2).

**For audit use only; do not use in production.** Returns `nil` if all verifications succeed, or `ErrVerificationFailed` (or another error) otherwise.

---

The [QuantumCoin](https://QuantumCoin.org) blockchain uses these hybrid PQC schemes.
