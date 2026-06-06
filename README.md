<img src=".etc/icon.png" align="right" height="300" width="300"/>

# CIRCL

**CIRCL** (Cloudflare Interoperable, Reusable Cryptographic Library) is a collection
of cryptographic primitives written in Go. The goal of this library is to be used as a tool for
experimental deployment of cryptographic algorithms targeting Post-Quantum (PQ) and Elliptic
Curve Cryptography (ECC).

## Security Disclaimer

🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental. All security issues must be reported, please notify us immediately following the instructions given in our [Security Policy](https://github.com/quantumcoinproject/circl/security/policy).

## About This Fork: Hybrid Signature Schemes

This repository is a **fork of CIRCL** that adds **hybrid digital signature schemes** combining classical (Ed25519) and post-quantum (lattice-based and hash-based) components. Hybrid signatures reduce single-point-of-failure risk: if one algorithm family is broken — whether classical or PQC — the remaining components still protect authenticity. The [QuantumCoin blockchain](https://quantumcoin.org) uses these hybrid PQC signature schemes.

### Hybrid DSA Schemes

| Scheme ID | Package | Mode | Components | PK + Sig | Verify ops/s¹ |
|:---------:|---------|------|------------|----------|:-------------:|
| 1 | [hybrideds](./sign/hybrideds) | Compact | Ed25519 + Dilithium (SPHINCS+ key present, not signed) | 3,966 B | ~10,970 |
| 2 | [hybrideds](./sign/hybrideds) | Full | Ed25519 + Dilithium + SPHINCS+ SHAKE-256f | 53,782 B | ~270 |
| 3 | [hybridedmldsaslhdsa](./sign/hybridedmldsaslhdsa) | Compact | Ed25519 + ML-DSA-44 (SLH-DSA key present, not signed) | 3,926 B | ~9,980 |
| 4 | [hybridedmldsaslhdsa](./sign/hybridedmldsaslhdsa) | Full | Ed25519 + ML-DSA-44 + SLH-DSA SHAKE-256f | 53,782 B | ~290 |
| 5 | [hybridedmldsaslhdsa5](./sign/hybridedmldsaslhdsa5) | Full | Ed25519 + ML-DSA-87 + SLH-DSA SHAKE-256s (NIST Level 5) | 37,205 B | ~470 |

¹ Verify operations per second measured with `go test -bench` on an `AMD Ryzen 7 5800X` (single-threaded, Go 1.24, Windows/amd64).

These hybrid schemes do not modify any underlying cryptographic primitive; each component algorithm is invoked exactly as specified by its NIST standard. This approach is consistent with NIST guidance on combining NIST-approved and post-quantum signature algorithms as a transition strategy to post-quantum cryptography (see [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)).

**Compact mode** signs with Ed25519 and the lattice-based component only (ML-DSA or Dilithium). The hash-based component's (SLH-DSA / SPHINCS+) public key is part of the composite key but is not used for signing — keeping signatures small and verification fast. **Full mode** signs with all three components; it can serve as a **break-glass** mechanism (activated when an imminent threat is detected) or as the default signing mode for maximum assurance.

Schemes 3–5 conform to finalized NIST standards: ML-DSA ([FIPS 204]), SLH-DSA ([FIPS 205]), and Ed25519 ([FIPS 186-5] § 7.8). They use context strings for domain separation in ML-DSA and SLH-DSA signing. **For new designs, prefer schemes 3–5.** Schemes 1–2 use pre-final NIST drafts (Dilithium / SPHINCS+) and a nonce-based compact construction; see the [hybrideds README](./sign/hybrideds/README.md) for details.

### Audit and independent verification

For **audit, validation, and independent per-component verification** of hybrid signatures (e.g. cross-checking against [PQClean](https://github.com/PQClean/PQClean), [liboqs](https://github.com/open-quantum-safe/liboqs), or other implementations), see the **[hybridparser](./sign/hybridparser)** package. It provides:

- **ParseHybrid**: verify a hybrid signature and extract per-component public keys and signatures (hex-encoded) for independent re-verification.
- **CheckHybrid**: reconstruct and verify using both the composite hybrid verifier and each component's verifier.

The [hybridparser README](./sign/hybridparser/README.md) describes how to decode the hex components and pass them to external DSA implementations for conformance audits against FIPS 204, FIPS 205, and FIPS 186-5. **Use hybridparser for audit and tooling only; production verification must use each hybrid scheme's own APIs.**

## Installation

You can get CIRCL by fetching:

```sh
go get -u github.com/quantumcoinproject/circl
```

Alternatively, look at the [Cloudflare Go](https://github.com/quantumcoinproject/go/tree/cf) fork to see how to integrate CIRCL natively in Go.

## List of Algorithms

[FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
[FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205

### Post-Quantum Cryptography

| KEM: Key Encapsulation Methods |
|:---:|

 - [ML-KEM](./kem/mlkem): modes 512, 768, 1024 ([FIPS-203](https://doi.org/10.6028/NIST.FIPS.203)).
 - [X25519MLKEM768](./kem/hybrid): hybrid KEM of ML-KEM-768 and X25519 ([draft-kwiatkowski-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/)).

| Digital Signature Schemes |
|:---:|

 - [Dilithium](./sign/dilithium): modes 2, 3, 5 ([Dilithium](https://pq-crystals.org/dilithium/)).
 - [ML-DSA](./sign/mldsa): modes 44, 65, 87 ([FIPS 204]).
 - [SLH-DSA](./sign/slhdsa): twelve parameter sets, pure and pre-hash signing ([FIPS 205]).

### Symmetric Cryptography

| XOF: eXtendable Output Functions |
|:---:|

 - [SHAKE128 and SHAKE256](./xof) ([FIPS 202]).
 - [BLAKE2X](./xof): BLAKE2XB and BLAKE2XS ([Blake2x](https://www.blake2.net/blake2x.pdf))
 - [KangarooTwelve](./xof/k12): fast hashing based on Keccak-p. ([KangarooTwelve](https://keccak.team/kangarootwelve.html)).
 - SIMD [Keccak](https://keccak.team/keccak_specs_summary.html) f1600 Permutation.

### Misc

| Integers |
|:---:|

- Safe primes generation.
- Integer encoding: wNAF, regular signed digit, mLSBSet representations.

| Finite Fields |
|:---:|

 - Fp25519.

## Testing and Benchmarking

Library comes with number of make targets which can be used for testing and
benchmarking:

- ``test`` performs testing of the binary.
- ``bench`` runs benchmarks.
- ``cover`` produces coverage.
- ``lint`` runs set of linters on the code base.

## Contributing

To contribute, fork this repository and make your changes, and then make a Pull
Request. A Pull Request requires approval of the admin team and a successful
CI build.

## How to Cite

To cite CIRCL, use one of the following formats and update the version and date you accessed this project.

APA Style

```
Faz-Hernandez, A. and Kwiatkowski, K. (2019). Introducing CIRCL:
An Advanced Cryptographic Library. Cloudflare. Available at
https://github.com/cloudflare/circl. v1.6.1 Accessed Apr, 2025.
```

BibTeX Source

```bibtex
@manual{circl,
  title        = {Introducing CIRCL: An Advanced Cryptographic Library},
  author       = {Armando Faz-Hernandez and Kris Kwiatkowski},
  organization = {Cloudflare},
  abstract     = {{CIRCL (Cloudflare Interoperable, Reusable Cryptographic Library) is
                   a collection of cryptographic primitives written in Go. The goal
                   of this library is to be used as a tool for experimental
                   deployment of cryptographic algorithms targeting Post-Quantum (PQ)
                   and Elliptic Curve Cryptography (ECC).}},
  note         = {Available at \url{https://github.com/cloudflare/circl}. v1.6.1 Accessed Apr, 2025},
  month        = jun,
  year         = {2019}
}
```

CFF Style

See attached [CITATION.cff](CITATION.cff) file.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
