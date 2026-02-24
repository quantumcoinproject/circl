# Hybrid ML-DSA-44 + SLH-DSA-SHAKE-256f + Ed25519 (hybridedmldsaslhdsa)

This package implements **hybrid-ML-DSA-44-SLH-DSA-SHAKE-256f-Ed25519**: a hybrid post-quantum cryptography digital signature scheme combining ML-DSA-44 (FIPS 204), SLH-DSA-SHAKE-256f (FIPS 205), and Ed25519. It supports both **compact** and **full (break-glass)** signing modes with the same key pair.

## Compact vs Full Mode — Break-glass

- **Compact mode** uses only ML-DSA-44 and Ed25519 to sign. Verification requires both Ed25519 and ML-DSA-44 to succeed. Signatures are smaller and verification is faster compared to Full-mode. The SLH-DSA key is still part of the composite public key (and of address derivation) but is not used for signing in normal operation. This keeps throughput and storage cost low on the chain.
  - **Context for signing (compact mode):** When signing with ML-DSA-44 in compact mode, the **context** input to ML-DSA-44 is the **scheme ID byte (0x03)** concatenated with the **SLH-DSA public key** (64 bytes): `context = 0x03 || pk_SLH-DSA`. This binds the compact signature to the composite key and ensures domain separation from full mode. Ed25519 signs the message only (no context).
- **Full mode (break-glass)** uses all three components — ML-DSA-44, SLH-DSA-SHAKE-256f, and Ed25519 — to sign. Verification requires all three to succeed. A blockchain may use full mode in two ways: (1) **Break-glass / emergency:** switch to requiring full mode (e.g. by block height or governance) when facing an imminent threat (e.g. CRQC or a break of ML-DSA-44). Full mode also enables **retroactive verification**: if both ML-DSA-44 and Ed25519 are later broken, the SLH-DSA component still attests to past signatures signed with the same key pair. (2) **Regular signing:** a blockchain can use full mode for all transactions if it prefers maximum assurance; the tradeoff is larger signature and public key sizes and higher sign and verify times.
- The same key pair is used for both modes; only the signing and verification policy (compact vs full) changes. Break-glass is a **policy switch**, not a key rollover.

## When to use

- **Blockchains and long-lived protocols** where the composite key pair is the signer’s sole cryptographic identity and rollback is not possible. Hybrid signatures reduce single-point-of-failure if one algorithm is broken (classical or PQC).
- **Normal operation:** use **compact** mode for smaller signatures and faster verification (ML-DSA-44 + Ed25519 only).
- **Break-glass / emergency:** use **full** mode when the chain requires all three components (e.g. imminent CRQC threat or ML-DSA-44 break). Full mode also allows retroactive verification if both ML-DSA-44 and Ed25519 are later broken.

## Verification rule

**Verification of all schemes involved in signing must succeed.** In compact mode, both ML-DSA-44 and Ed25519 must verify. In full mode, ML-DSA-44, SLH-DSA, and Ed25519 must all verify. A signature is valid only when every component verification passes.

## Key usage (identity)

This hybrid scheme is designed for use in blockchain protocols where **the composite key pair is the signer’s sole cryptographic identity**. Individual component keys (ML-DSA-44, SLH-DSA, Ed25519) **MUST NOT** be reused in any other signing context — whether standalone, in a different hybrid combination, or across protocol boundaries.

## Signature scheme ID (first byte)

For blockchains that support multiple signature schemes, the **first byte** of every signature identifies the scheme and mode so verifiers can dispatch without separate metadata:

| First byte (Scheme ID) | Mode   | Description                                      |
|------------------------|--------|--------------------------------------------------|
| **3**                  | Compact| ML-DSA-44 + Ed25519 only                         |
| **4**                  | Full   | ML-DSA-44 + SLH-DSA-SHAKE-256f + Ed25519 (break-glass) |

## NIST / FIPS specifications

Component algorithms conform to:

| Component    | Specification | Link |
|-------------|---------------|------|
| **ML-DSA-44** | FIPS 204 (Module-Lattice-Based Digital Signature Standard) | [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) |
| **SLH-DSA**   | FIPS 205 (Stateless Hash-Based Digital Signature Standard) | [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) |
| **Ed25519**   | FIPS 186-5 (Digital Signature Standard), § 7.8 (EdDSA)    | [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5) |

The underlying algorithms are unchanged; the hybrid layer concatenates keys and signatures, applies context strings for domain separation in ML-DSA and SLH-DSA signing (see below), and requires all component verifications to succeed. This approach is consistent with NIST guidance on combining NIST-approved and post-quantum signature algorithms as a transition strategy to post-quantum cryptography (see [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)).

## Compact vs full: motivation

- **Compact:** Smaller signature and faster verification by signing with ML-DSA-44 and Ed25519 only. Randomized signing is used for ML-DSA-44. The SLH-DSA public key is still part of the composite public key and address; it is used in break-glass or for retroactive verification. **Context for ML-DSA-44 in compact mode:** `context = 0x03 || pk_SLH-DSA` (1-byte scheme ID 3 followed by the 64-byte SLH-DSA public key). Verification requires both Ed25519 and ML-DSA-44 to succeed.
- **Full (break-glass or regular):** All three schemes (ML-DSA-44, SLH-DSA, Ed25519) sign the message. Randomized signing is used for both ML-DSA-44 and SLH-DSA. Both use the 1-byte scheme ID (0x04) as their context string. Verification requires all three — Ed25519, ML-DSA-44, and SLH-DSA — to succeed. A chain may use full mode for break-glass only or for all signing; using full for regular signing trades larger signature/public key and higher sign/verify times for maximum assurance.

## Private key layout

**Total size: 4064 bytes**

| Offset | Length (bytes) | Content                              |
|--------|----------------|--------------------------------------|
| 0      | 64             | Ed25519 secret key (with public key) |
| 64     | 2560           | ML-DSA-44 secret key                 |
| 2624   | 1312           | ML-DSA-44 public key                 |
| 3936   | 128            | SLH-DSA secret key (with public key) |

## Public key layout

**Total size: 1408 bytes**

| Offset | Length (bytes) | Content           |
|--------|----------------|--------------------|
| 0      | 32             | Ed25519 public key |
| 32     | 1312           | ML-DSA-44 public key |
| 1344   | 64             | SLH-DSA public key |

## Signature layout

### Compact signature (Scheme ID = 3)

**Total size: 2518 bytes** for a 32-byte message (`1 + 1 + 64 + 2420 + 32`). Message length is 32 bytes.

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 1              | **Scheme ID (3)**           |
| 1      | 1              | Message length (32)        |
| 2      | 64             | Ed25519 signature          |
| 66     | 2420           | ML-DSA-44 signature        |
| 2486   | 32             | Original message           |

### Full signature (Scheme ID = 4, break-glass)

**Total size: 52,374 bytes** for a 32-byte message (`1 + 1 + 64 + 32 + 2420 + 49856`). Message length is 32 bytes.

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 1              | **Scheme ID (4)**           |
| 1      | 1              | Message length (32)        |
| 2      | 64             | Ed25519 signature          |
| 66     | 32             | Original message           |
| 98     | 2420           | ML-DSA-44 signature        |
| 2518   | 49856          | SLH-DSA signature          |

## Audit / verification

For independent audit, per-component verification, and parsing of hybrid signatures (e.g. to verify alignment with FIPS 204, FIPS 205, FIPS 186-5), see the [hybridparser](../hybridparser/README.md) package. **Use hybridparser for audit and tooling only; production verification must use this package’s APIs** (`Verify`, `VerifyCompact`).

## Summary

| Item           | Compact | Full (break-glass) |
|----------------|---------|---------------------|
| Public key     | 1408 B  | 1408 B              |
| Private key    | 4064 B  | 4064 B              |
| Signature (32 B msg) | 2518 B | 52,374 B        |
| Verify ops/s¹  | ~9,980  | ~290                |
| Scheme ID      | 3       | 4                    |

¹ Verify operations per second measured with `go test -bench` on an AMD Ryzen 7 5800X (single-threaded, Go 1.24, Windows/amd64).

For the full specification and whitepaper context, see [docs/HYBRID_PQC_SIGNATURE_SPEC.md](../../docs/HYBRID_PQC_SIGNATURE_SPEC.md).

---

The [QuantumCoin](https://QuantumCoin.org) blockchain uses these hybrid PQC schemes.
