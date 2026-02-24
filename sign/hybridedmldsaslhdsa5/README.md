# Hybrid ML-DSA-87 + SLH-DSA-SHAKE-256s + Ed25519 (hybridedmldsaslhdsa5)

This package implements **hybrid-ML-DSA-87-SLH-DSA-SHAKE-256s-Ed25519**: a hybrid post-quantum cryptography digital signature scheme combining ML-DSA-87 (FIPS 204), SLH-DSA-SHAKE-256s (FIPS 205), and Ed25519. Both PQC components are **NIST Level 5**. This scheme supports **full** signing only (no compact mode); it offers higher assurance at the cost of larger keys and signatures.

## Full mode only

This scheme has **full mode only** (no compact mode, no break-glass). Every signature uses all three components — ML-DSA-87, SLH-DSA-SHAKE-256s, and Ed25519 — and verification requires all three to succeed. A blockchain can use this scheme for **regular signing** when it requires maximum assurance (two NIST Level 5 PQC algorithms plus Ed25519). The tradeoff is larger signature and public key sizes, and higher sign and verify times. On a chain that supports multiple hybrid schemes, Scheme ID 5 can be selected when higher gas cost or lower throughput is acceptable.

## When to use

- **Blockchains and long-lived protocols** where the composite key pair is the signer’s sole cryptographic identity and maximum assurance is required. Suitable when larger signature size and verification cost are acceptable (e.g. higher gas fee or lower throughput).
- **High-assurance use cases** that want two NIST Level 5 algorithms from different families (lattice-based ML-DSA-87 and hash-based SLH-DSA-SHAKE-256s) plus Ed25519.

## Verification rule

**Verification of all schemes involved in signing must succeed.** For this scheme, ML-DSA-87, SLH-DSA, and Ed25519 must all verify. A signature is valid only when every component verification passes.

## Key usage (identity)

This hybrid scheme is designed for use in blockchain protocols where **the composite key pair is the signer’s sole cryptographic identity**. Individual component keys (ML-DSA-87, SLH-DSA, Ed25519) **MUST NOT** be reused in any other signing context — whether standalone, in a different hybrid combination, or across protocol boundaries.

## Signature scheme ID (first byte)

For blockchains that support multiple signature schemes, the **first byte** of every signature identifies the scheme so verifiers can dispatch without separate metadata:

| First byte (Scheme ID) | Mode | Description                                        |
|-------------------------|------|----------------------------------------------------|
| **5**                   | Full | ML-DSA-87 + SLH-DSA-SHAKE-256s + Ed25519 (full only) |

## NIST / FIPS specifications

Component algorithms conform to:

| Component    | Specification | Link |
|-------------|---------------|------|
| **ML-DSA-87** | FIPS 204 (Module-Lattice-Based Digital Signature Standard) | [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) |
| **SLH-DSA**   | FIPS 205 (Stateless Hash-Based Digital Signature Standard) | [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) |
| **Ed25519**   | FIPS 186-5 (Digital Signature Standard), § 7.8 (EdDSA)    | [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5) |

The underlying algorithms are unchanged; the hybrid layer concatenates keys and signatures, applies a context string for domain separation in ML-DSA and SLH-DSA signing (see below), and requires all component verifications to succeed. This approach is consistent with NIST guidance on combining NIST-approved and post-quantum signature algorithms as a transition strategy to post-quantum cryptography (see [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)).

## Signing context

All three components sign the message. Randomized signing is used for ML-DSA-87 and SLH-DSA. Both ML-DSA-87 and SLH-DSA use the 1-byte scheme ID (0x05) as their context string for domain separation. Ed25519 signs the message directly (Ed25519 does not use a context parameter).

## Private key layout

**Total size: 7680 bytes**

| Offset | Length (bytes) | Content                              |
|--------|----------------|--------------------------------------|
| 0      | 64             | Ed25519 secret key (with public key) |
| 64     | 4896           | ML-DSA-87 secret key                 |
| 4960   | 2592           | ML-DSA-87 public key                 |
| 7552   | 128            | SLH-DSA secret key (with public key) |

## Public key layout

**Total size: 2688 bytes**

| Offset | Length (bytes) | Content             |
|--------|----------------|---------------------|
| 0      | 32             | Ed25519 public key   |
| 32     | 2592           | ML-DSA-87 public key |
| 2624   | 64             | SLH-DSA public key   |

## Signature layout (full only)

**Total size: 34,517 bytes** for a 32-byte message (`1 + 1 + 64 + 32 + 4627 + 29792`). Message length is 32 bytes.

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 1              | **Scheme ID (5)**           |
| 1      | 1              | Message length (32)        |
| 2      | 64             | Ed25519 signature          |
| 66     | 32             | Original message           |
| 98     | 4627           | ML-DSA-87 signature        |
| 4725   | 29792          | SLH-DSA signature         |

## Audit / verification

For independent audit, per-component verification, and parsing of hybrid signatures (e.g. to verify alignment with FIPS 204, FIPS 205, FIPS 186-5), see the [hybridparser](../hybridparser/README.md) package. **Use hybridparser for audit and tooling only; production verification must use this package’s APIs** (`Verify`).

## Summary

| Item                 | Value      |
|----------------------|------------|
| Public key           | 2688 B     |
| Private key           | 7680 B     |
| Signature (32 B msg) | 34,517 B   |
| Verify ops/s¹        | ~470       |
| Scheme ID            | 5          |

¹ Verify operations per second measured with `go test -bench` on an AMD Ryzen 7 5800X (single-threaded, Go 1.24, Windows/amd64).

For the full specification and whitepaper context, see [docs/HYBRID_PQC_SIGNATURE_SPEC.md](../../docs/HYBRID_PQC_SIGNATURE_SPEC.md).

---

The [QuantumCoin](https://QuantumCoin.org) blockchain uses these hybrid PQC schemes.
