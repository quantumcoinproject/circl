# hybrideds — Hybrid Dilithium (ML-DSA-44) + SPHINCS+ (SLH-DSA-SHAKE-256f) + Ed25519

This package implements a hybrid post-quantum cryptography digital signature scheme combining **Dilithium** (ML-DSA-44), **SPHINCS+** (SLH-DSA-SHAKE-256f), and Ed25519. It supports both **compact** (Scheme ID 1) and **full** (Scheme ID 2) signing modes with the same key pair. The implementation uses the same algorithm packages as the finalized NIST schemes (ML-DSA-44, SLH-DSA) but the compact-mode construction differs from the NIST-oriented hybrids (see below).

**For new designs and blockchains, prefer the finalized NIST-standard hybrids:** use [hybridedmldsaslhdsa](../hybridedmldsaslhdsa/README.md) (ML-DSA-44 + SLH-DSA-SHAKE-256f + Ed25519, compact + break-glass) or [hybridedmldsaslhdsa5](../hybridedmldsaslhdsa5/README.md) (ML-DSA-87 + SLH-DSA-SHAKE-256s + Ed25519, full only) instead of this package. Those packages are aligned with FIPS 204 and FIPS 205 and use a compact construction that does not require a nonce in the signature.

## Compact vs Full Mode

- **Compact mode (Scheme ID 1)** signs only with Ed25519 and Dilithium (ML-DSA-44). The SLH-DSA (SPHINCS+) key is part of the composite public key but is not used for signing in compact mode. To bind the signature to the composite key without signing the raw message with all three algorithms, compact mode forms a **hybrid message** that is hashed and then signed by Ed25519 and Dilithium:
  - **Hybrid message:** `nonce (40 bytes) || original message (1–64 bytes) || SLH-DSA public key (64 bytes)`.
  - **Signed value:** `hybrid-message-hash = SHA3-512(hybrid message)`. Ed25519 and Dilithium sign this hash.
  - The **40-byte nonce** is freshly generated at random for each compact signature. It is included in the signature so that verifiers can reconstruct the same hybrid message and hash, then verify the Ed25519 and Dilithium signatures. The nonce ensures the signed hash is unique per signature and binds the signature to this composite key.
- **Full mode (Scheme ID 2)** signs with all three components — Ed25519, Dilithium (ML-DSA-44), and SPHINCS+ (SLH-DSA) — over the message directly. No nonce or context string; verification requires all three to succeed.

## Verification rule

**Verification of all schemes involved in signing must succeed.** In compact mode, both Ed25519 and ML-DSA-44 (Dilithium) must verify (over the reconstructed SHA3-512 hash of nonce || message || SLH-DSA public key). In full mode, Ed25519, ML-DSA-44, and SLH-DSA must all verify over the message. A signature is valid only when every component verification passes.

## Signature scheme ID (first byte)

| First byte (Scheme ID) | Mode   | Description                                      |
|------------------------|--------|--------------------------------------------------|
| **1**                  | Compact| Ed25519 + Dilithium (ML-DSA-44); 40-byte nonce in signature |
| **2**                  | Full   | Ed25519 + Dilithium (ML-DSA-44) + SPHINCS+ (SLH-DSA-SHAKE-256f) |

## NIST / FIPS and use of finalized standards

The **HybridEds** package (Scheme IDs 1 and 2) uses Dilithium and SPHINCS+, which were specified in pre-final NIST drafts. Their wire formats may differ from the finalized **ML-DSA** (FIPS 204) and **SLH-DSA** (FIPS 205). For FIPS-aligned implementations and a compact mode that does not require a nonce in the signature, use:

- [hybridedmldsaslhdsa](../hybridedmldsaslhdsa/README.md) — ML-DSA-44 + SLH-DSA-SHAKE-256f + Ed25519 (compact + full break-glass).
- [hybridedmldsaslhdsa5](../hybridedmldsaslhdsa5/README.md) — ML-DSA-87 + SLH-DSA-SHAKE-256s + Ed25519 (full only).

## Private key layout

**Total size: 4064 bytes**

| Offset | Length (bytes) | Content                              |
|--------|----------------|--------------------------------------|
| 0      | 64             | Ed25519 secret key (with public key) |
| 64     | 2560           | ML-DSA-44 (Dilithium) secret key     |
| 2624   | 1312           | ML-DSA-44 public key                 |
| 3936   | 128            | SLH-DSA (SPHINCS+) secret key (with public key) |

## Public key layout

**Total size: 1408 bytes**

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 32             | Ed25519 public key         |
| 32     | 1312           | ML-DSA-44 (Dilithium) public key |
| 1344   | 64             | SLH-DSA (SPHINCS+) public key     |

## Signature layout

### Compact signature (Scheme ID = 1)

**Total size: 2558 bytes** for a 32-byte message (`1 + 1 + 64 + 2420 + 40 + 32`). Message length is 32 bytes.

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 1              | **Scheme ID (1)**           |
| 1      | 1              | Message length (32)        |
| 2      | 64             | Ed25519 signature          |
| 66     | 2420           | ML-DSA-44 (Dilithium) signature |
| 2486   | 40             | **Random nonce** (used to form hybrid message for verification) |
| 2526   | 32             | Original message           |

### Full signature (Scheme ID = 2)

**Total size: 52,374 bytes** for a 32-byte message (`1 + 1 + 64 + 32 + 2420 + 49856`). Message length is 32 bytes.

| Offset | Length (bytes) | Content                    |
|--------|----------------|----------------------------|
| 0      | 1              | **Scheme ID (2)**           |
| 1      | 1              | Message length (32)        |
| 2      | 64             | Ed25519 signature          |
| 66     | 32             | Original message           |
| 98     | 2420           | ML-DSA-44 (Dilithium) signature |
| 2518   | 49856          | SLH-DSA (SPHINCS+) signature |

## Audit / verification

For independent audit, per-component verification, and parsing of hybrid signatures (including the 40-byte nonce for scheme 1), see the [hybridparser](../hybridparser/README.md) package. **Use hybridparser for audit and tooling only; production verification must use this package’s APIs** (`Verify`, `VerifyCompact`).

## Summary

| Item           | Compact | Full   |
|----------------|---------|--------|
| Public key     | 1408 B  | 1408 B |
| Private key    | 4064 B  | 4064 B |
| Signature (32 B msg) | 2558 B | 52,374 B |
| Verify ops/s¹  | ~10,970 | ~270   |
| Scheme ID      | 1       | 2      |

¹ Verify operations per second measured with `go test -bench` on an AMD Ryzen 7 5800X (single-threaded, Go 1.24, Windows/amd64).

This hybrid scheme does not modify any underlying cryptographic primitive; each component algorithm (Dilithium/ML-DSA-44, SPHINCS+/SLH-DSA, Ed25519) is invoked exactly as specified by its standard. This approach is consistent with NIST guidance on combining NIST-approved and post-quantum signature algorithms as a transition strategy to post-quantum cryptography (see [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)).

For finalized NIST-standard hybrid schemes, see [hybridedmldsaslhdsa](../hybridedmldsaslhdsa/README.md) and [hybridedmldsaslhdsa5](../hybridedmldsaslhdsa5/README.md).

---


