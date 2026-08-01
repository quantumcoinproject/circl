# FINDING-000: seed expander discards a third of its 96-byte input

| | |
|---|---|
| **Status** | Open — documented, not fixed (construction is frozen for wallet compatibility) |
| **Affects** | `sign/hybrideds/seed_expander.go` (`ExpandSeed`) |
| **Class** | Entropy accounting; under-specified precondition; non-injective key derivation |
| **CWE** | [CWE-1068] (Inconsistency Between Implementation and Documented Design). [CWE-331] (Insufficient Entropy) is the failure mode *if* the positional precondition is violated — not the current state. |
| **Severity** | **Low** — reduced margin, no path to forgery or key recovery under any examined configuration. Rated per the scale in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md#methodology). |
| **Reachability** | **Not reachable** — all three consumers source base seeds from a CSPRNG. |
| **Security-strength assessment** | **Requirement met, with no headroom above it.** Each component receives seed min-entropy ≥ its target security strength, per [SP 800-133r2] §5.1 and the security-strength definition in [SP 800-57 Pt.1 r5] §5.6.1. See [Standards assessment](#standards-assessment). |
| **Formal conformance claim** | **None made, and none available.** This scheme realizes the *pre-final draft* algorithms [Dilithium2] and [SPHINCS+-SHAKE-256f-simple], which predate [FIPS 204] and [FIPS 205]; there is no FIPS key-generation conformance to claim, and this is not a [CMVP]-validated module. |
| **Impact on current consumers** | **None.** All supply CSPRNG output. See [Applicability](#applicability). |
| **Reproduction** | `sign/hybrideds/seedentropy_test.go` |

Sibling schemes `sign/hybridedmldsaslhdsa` and `sign/hybridedmldsaslhdsa5` are **not**
affected: their expanders absorb the entire base seed under an ASCII domain string. This
finding is specific to the legacy `hybrideds` expander.

---

## A note on algorithm names

`sign/hybrideds` implements **scheme IDs 1 and 2**, which are wire-compatible with the
pre-standardization NIST PQC Round 3 submissions, **not** with the finalized FIPS algorithms.
The Go identifiers are misleading on this point and are worth stating precisely once:

| Component | Go package / call | Algorithm actually realized | Specification |
|---|---|---|---|
| Classical | `sign/ed25519` | Ed25519 (pure) | [RFC 8032] §5.1; [FIPS 186-5] §7.8 |
| Lattice | `mldsa44.GenerateKeyInternal(_, false)`, `mldsa44.SignNoContext` | **Dilithium2** (CRYSTALS-Dilithium v3.1) | [Dilithium2] |
| Hash-based | `slhdsa.SHAKE_256f`, `slhdsa.SignRandomizedNoContext` | **SPHINCS+-SHAKE-256f-simple** (SPHINCS+ v3.1) | [SPHINCS+-SHAKE-256f-simple] |

The `nist=false` flag to `GenerateKeyInternal` omits the `{K,L}` domain-separation bytes that
[FIPS 204] added, reproducing Round 3 Dilithium2 key generation. `SignNoContext` /
`SignRandomizedNoContext` bypass the `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` message encoding that
[FIPS 204] §5.2 and [FIPS 205] §10.2 introduced, reproducing Round 3 signing. The FIPS-era
implementations are reused as *code*; the *algorithms* realized are the drafts.

Throughout this document, **Dilithium2** and **SPHINCS+-SHAKE-256f-simple** refer to these
draft algorithms. The finalized ML-DSA-44 and SLH-DSA-SHAKE-256f appear only in
`sign/hybridedmldsaslhdsa` (IDs 3–4) and `sign/hybridedmldsaslhdsa5` (ID 5), which this
finding does not concern.

## Summary

`ExpandSeed` takes a 96-byte base seed and produces the 160-byte seed used to generate the
Ed25519 + Dilithium2 + SPHINCS+-SHAKE-256f-simple composite key. Only **64 of those 96 bytes
reach the construction**. The 32 bytes at odd indices below 64 are copied nowhere and absorbed
nowhere; they are discarded.

The behaviour is deliberate, documented in the source, and retained for backward compatibility
with deployed wallets. It is recorded here for three reasons: the resulting entropy budget
leaves the strongest component sitting *exactly on* its required security strength, with no
headroom above it; the stated precondition on the caller is **necessary but not sufficient**;
and the derivation is **not injective**, which has consequences for tooling that treats a base
seed as a wallet identifier.

**This is not a break.** Under the uniformly random base seed that every consumer actually
supplies, every component receives seed entropy at or above its target security strength.

> **Read "no headroom" carefully.** It does *not* mean the keys have little or no entropy. Each
> component receives at least the full entropy its parameter set requires — 256 bits where 256
> are required. The observation is only that the strongest component, SPHINCS+-SHAKE-256f-simple,
> lands **exactly on** its requirement rather than above it, so it has no surplus to absorb a
> future reduction in seed quality. The other two components retain roughly 128 bits of surplus
> each.

## Structure

```
baseSeed[0:64)  even indices (0,2,…,62)  ─── 32 B ──► SHAKE256 ──► Ed25519 seed   (32 B)
                                                             └──► SPHINCS+ seed  (96 B)
                                                                  = SK.seed ‖ SK.prf ‖ PK.seed
baseSeed[0:64)  odd  indices (1,3,…,63)  ─── 32 B ──►  DISCARDED
baseSeed[64:96)                          ─── 32 B ──►  Dilithium2 seed (verbatim pass-through)
```

The 32 absorbed bytes are placed at even positions of a 64-byte block whose odd positions are
zero, then `0x02` is appended as an ad-hoc domain separator and 128 bytes are squeezed. The
zero-interleaving adds no entropy; it is a legacy artefact of the original C implementation.

Confirmed by execution (`TestExpandSeedInfluenceMap`): flipping one bit in each of the 96
positions in turn changes the output for exactly 64 positions and leaves it unchanged for
exactly 32 — and those 32 are precisely the odd indices below 64.

## Entropy accounting

For a uniformly random base seed:

| Branch | Input | Feeds | Min-entropy |
|---|---|---|---|
| XOF | `base[0:64)` even indices, 32 B | Ed25519 seed **and** all SPHINCS+ seed material | 256 bits, **shared** |
| Pass-through | `base[64:96)`, 32 B | Dilithium2 seed | 256 bits, independent |
| Discarded | `base[0:64)` odd indices, 32 B | — | 256 bits, **lost** |

768 bits supplied; 512 bits effective; 256 bits discarded.

Per component, against the target security strength of its parameter set. "Category" is the
NIST PQC security category as defined in the [PQC call for proposals][pqc-categories] §4.A.5;
"security strength" is as defined in [SP 800-57 Pt.1 r5] §5.6.1; "min-entropy" as in
[SP 800-90B] §3.1:

| Component | Specification | PQC category | Target strength | Seed entropy received | Margin |
|---|---|---|---|---|---|
| Ed25519 | [RFC 8032] / [FIPS 186-5] §7.8 | ≈ 1 | ~128 bits | 256 bits (XOF branch) | +128 |
| Dilithium2 | [Dilithium2] | 2 | ~128 bits | 256 bits (pass-through) | +128 |
| SPHINCS+-SHAKE-256f-simple | [SPHINCS+-SHAKE-256f-simple] | **5** | **256 bits** | **256 bits** (XOF branch) | **0** |

## Standards assessment

Two distinct questions are worth separating, because the answers differ.

### 1. Is the security-strength requirement met? — Yes, but with no headroom

The governing requirement is [SP 800-133r2] *Recommendation for Cryptographic Key Generation*,
§5.1 (*Key Pairs for Digital Signature Schemes*), read with §4: keying material must derive
from an approved RBG whose security strength is at least that of the key being generated.

- **Ed25519** and **Dilithium2** each receive 256 bits against ~128-bit targets: comfortable.
- **SPHINCS+-SHAKE-256f-simple** receives 256 bits against a 256-bit target: satisfied
  *exactly*.

The relevant floor for a 256-bit security strength is 256 bits of entropy input, consistent
with the instantiation requirement in [SP 800-90A r1] §8.6.3 (*Entropy Input*).

**Derivation function.** SHAKE256 is an approved extendable-output function ([FIPS 202] §6.2)
providing 256-bit security. Squeezing 128 bytes from a 256-bit absorbed input produces output
computationally indistinguishable from random at the 256-bit level, but carrying no more than
256 bits of true entropy. That is the level required — not less, and not more.

### 2. Is this FIPS-conformant key generation? — The question does not apply

Schemes 1 and 2 implement Round 3 draft algorithms, so there is no FIPS 204 or FIPS 205
key-generation conformance available to claim in the first place. Two further points hold even
if one substitutes the finalized successors:

[SPHINCS+-SHAKE-256f-simple] specifies that `SK.seed`, `SK.prf` and `PK.seed` — 3 × 32 = 96
bytes at `n = 32` — are each drawn from a cryptographic RNG (the corresponding finalized
requirement is [FIPS 205] §10.1 Algorithm 21, `slh_keygen`). [Dilithium2] likewise draws a
fresh 32-byte seed ζ (finalized: [FIPS 204] Algorithm 1, `ML-DSA.KeyGen`, drawing ξ). Here all
96 SPHINCS+ bytes are instead produced deterministically from a single 256-bit value, so their
**joint** entropy is 256 bits rather than 768.

Deterministic derivation from a mnemonic is the standard and intended wallet pattern — it is
what makes seed-phrase recovery possible at all — but it is a departure from the key-generation
algorithms as written. Accordingly:

- **No FIPS key-generation conformance claim is made** for this path, and none is available
  for a draft-algorithm scheme.
- **This is not a [CMVP]-validated module**, and nothing here should be read as an
  approved-mode statement.
- What *is* asserted is the security-strength property in question 1: the derived SPHINCS+ key
  retains 256-bit security, matching PQC category 5 — "at least as hard to break as AES-256
  via exhaustive key search" ([PQC call for proposals][pqc-categories] §4.A.5). The reduction
  from 768 to 256 bits of seed entropy therefore does **not** push the component below its
  claimed category.

**What "no headroom" means in practice.** SPHINCS+-SHAKE-256f-simple is the one component
sitting exactly on its threshold. Any shortfall in the base seed's min-entropy — however small
— translates directly into a shortfall below category 5 for the hash-based layer, with nothing
absorbing it. The other two components have ~128 bits of headroom each and would tolerate
substantial degradation before falling below their targets. This asymmetry is worth stating
because the hash-based layer is the break-glass anchor: it is precisely the component one would
least like to be the weakest-seeded.

## The precondition is necessary but not sufficient

The source states:

> `baseSeed` MUST originate from a CSPRNG (or a KDF with >= 256 bits of min-entropy).

For CSPRNG output this is correct and sufficient: a uniform source is uniform on every subset
of positions, so the 32 absorbed bytes carry a full 256 bits.

For the parenthetical alternative it is **not** sufficient, and the gap is not subtle.
`ExpandSeed` is a function of 64 specific byte positions only. Min-entropy located anywhere
else contributes **exactly zero**. A 96-byte seed satisfying the stated requirement — 256 bits
of min-entropy overall — can therefore deliver anywhere between 0 and 256 bits to the XOF
branch, depending purely on where in the byte string that entropy sits. A source that happened
to concentrate its randomness in odd positions would produce a **constant** Ed25519 and
SPHINCS+ key pair while fully satisfying the documented contract.

The correct precondition is positional:

> The 32 bytes at even indices of `baseSeed[0:64)` must **on their own** carry ≥ 256 bits of
> min-entropy, and `baseSeed[64:96)` must **on its own** carry ≥ 256 bits.

No caller is known to violate this, because all of them use a CSPRNG. The defect is that the
contract as written would permit one to.

## Non-injectivity

Because 32 input bytes are ignored, `ExpandSeed` is not injective: each expanded seed has
`2^256` base-seed preimages. `TestExpandSeedIsNotInjective` confirms that two base seeds
differing in all 32 discarded positions produce byte-identical expanded seeds and hence a
byte-identical composite public key — the same wallet, the same funds, two distinct backups.

This is harmless for key secrecy but has concrete consequences for surrounding tooling:

- A base seed is **not** a unique wallet identifier. De-duplication, indexing, or
  "have I seen this seed before" logic keyed on base-seed bytes will treat colliding seeds as
  distinct while they control identical funds.
- Seed-phrase backups encode the full 96 bytes, so a third of every recorded phrase is inert.
  Corruption confined to those positions is undetectable and — conveniently — harmless, but
  round-tripping seed → key → seed cannot recover the original bytes.
- Any future integrity check over the base seed must not assume the key commits to all 96
  bytes, because it does not.

## Branch coupling

`TestExpandSeedBranchIndependence` pins the split: the XOF branch determines the Ed25519
**and** SPHINCS+ seeds, while Dilithium2 is fed independently.

Two of the three components therefore share a single 256-bit secret. Recovering it — 2^256
work under a uniform seed, so not a practical attack — collapses the hybrid to Dilithium2
alone, i.e. PQC category 2. The source comments address the *cryptographic* independence of
the two outputs under the random-oracle model, which is sound; they do not note that the
components share a **preimage**, which is a distinct property and the one relevant to a hybrid
construction's independent-failure premise.

The Dilithium2 pass-through is a deliberate and well-judged hedge in the same spirit: it means
a structural break in SHAKE256 cannot affect the lattice component at all.

## Applicability

**No exploitable path exists in `quantum-coin-go`, `quantum-coin-js-sdk`, or `quantumcoin.js`,
and no operational action is required.** Every base seed in all three originates from a
CSPRNG:

- `quantum-coin-js-sdk` — `newWalletSeedWords` obtains the base seed from
  `circl.cryptoRandom(baseSeedLen)`, which wraps Go's `crypto/rand` (host
  `crypto.getRandomValues` under WASM).
- `quantum-coin-go` — seeds are drawn from `crypto/rand.Reader`; `GenerateKeyWithReader` is
  only ever called with it, and checks the byte count before proceeding.
- `quantumcoin.js` — performs no key derivation of its own; `Wallet.createRandom` routes to
  the SDK path above.

Uniform output satisfies the positional precondition automatically, so the XOF branch receives
its full 256 bits and every component meets its target strength.

**Residual exposure is confined to future work**, specifically: introducing a mnemonic or
KDF-based base seed that is not uniform across byte positions; reducing base-seed size;
or building tooling that assumes base seeds are unique per wallet.

## Recommended actions

This expander is **frozen**: changing it would derive different wallets from every existing
seed phrase. The recommendations are therefore documentation and guard-rail changes, not
construction changes.

1. **Correct the precondition in the doc comment** to the positional form given above. This is
   the substantive fix and costs nothing.
2. **Record the zero-margin property** next to `AbsorbSize`, noting that
   SPHINCS+-SHAKE-256f-simple receives exactly its target 256 bits and that the constant is
   therefore a security parameter, not an implementation detail.
3. **State non-injectivity in the exported documentation**, so downstream tooling does not
   assume base seeds uniquely identify wallets.
4. **Correct the component names** in the package documentation. `hybrideds` realizes
   Dilithium2 and SPHINCS+-SHAKE-256f-simple, not ML-DSA-44 and SLH-DSA-SHAKE-256f; the Go
   identifiers invite the opposite reading and an auditor cross-checking against [FIPS 204] or
   [FIPS 205] test vectors would get a false mismatch.
5. **Do not extend this expander to new schemes.** The sibling packages already use the
   corrected design — full absorption of the base seed under an ASCII domain string
   (`"hybrid-ed-ml44-slhshake256f-64-160-v1"` and the level-5 equivalent) — which should
   remain the template.
6. If a base seed is ever sourced from anything other than a CSPRNG, **validate the
   positional entropy assumption first**; the aggregate figure is not sufficient.

## References

**Tests and source**

- Test: `sign/hybrideds/seedentropy_test.go` — influence map, non-injectivity, branch split
- Source: `sign/hybrideds/seed_expander.go`
- Contrast: `sign/hybridedmldsaslhdsa/seed_expander.go`, `sign/hybridedmldsaslhdsa5/seed_expander.go`

**Draft algorithm specifications (what schemes 1–2 actually implement)**

- [Dilithium2] — *CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation*, Version 3.1, 8 February 2021.
- [SPHINCS+-SHAKE-256f-simple] — *SPHINCS+ Submission to the NIST Post-Quantum Project*, v3.1, 10 June 2022.
- [PQC call for proposals][pqc-categories] — *Submission Requirements and Evaluation Criteria for the Post-Quantum Cryptography Standardization Process*, December 2016. §4.A.5 defines security categories 1–5.

**NIST standards and recommendations**

- [SP 800-133r2] — *Recommendation for Cryptographic Key Generation*, Rev. 2, June 2020.
- [SP 800-57 Pt.1 r5] — *Recommendation for Key Management: Part 1 – General*, Rev. 5, May 2020.
- [SP 800-90A r1] — *Recommendation for Random Number Generation Using Deterministic Random Bit Generators*, Rev. 1, June 2015.
- [SP 800-90B] — *Recommendation for the Entropy Sources Used for Random Bit Generation*, January 2018.
- [FIPS 202] — *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*, August 2015.
- [FIPS 186-5] — *Digital Signature Standard (DSS)*, February 2023.
- [FIPS 204] — *Module-Lattice-Based Digital Signature Standard*, August 2024. (Successor to Dilithium; **not** implemented by this scheme.)
- [FIPS 205] — *Stateless Hash-Based Digital Signature Standard*, August 2024. (Successor to SPHINCS+; **not** implemented by this scheme.)
- [RFC 8032] — *Edwards-Curve Digital Signature Algorithm (EdDSA)*, January 2017.
- [CMVP] — NIST Cryptographic Module Validation Program.

[Dilithium2]: https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
[SPHINCS+-SHAKE-256f-simple]: https://sphincs.org/data/sphincs+-r3.1-specification.pdf
[pqc-categories]: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf
[SP 800-133r2]: https://doi.org/10.6028/NIST.SP.800-133r2
[SP 800-57 Pt.1 r5]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
[SP 800-90A r1]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90B]: https://doi.org/10.6028/NIST.SP.800-90B
[FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
[FIPS 186-5]: https://doi.org/10.6028/NIST.FIPS.186-5
[FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[CMVP]: https://csrc.nist.gov/projects/cryptographic-module-validation-program

[CWE-1068]: https://cwe.mitre.org/data/definitions/1068.html
[CWE-331]: https://cwe.mitre.org/data/definitions/331.html
