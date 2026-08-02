# Security Audit — Findings Index

This document records the findings of an ongoing internal security review of this fork,
concentrating on the **fork-authored** code: the hybrid signature schemes
(`sign/hybridedmldsaslhdsa`, `sign/hybridedmldsaslhdsa5`, `sign/hybrideds`), their supporting
glue (`sign/hybridparser`, `sign/schemes`, `sign/wasm`), the KEM stack (`kem/`), and the seams
where they meet the inherited CIRCL primitives.

## Contents

- [Scope and method](#scope-and-method)
- [How to read this](#how-to-read-this)
- [Methodology](#methodology)
  - [Severity — the defect in the code itself](#severity--the-defect-in-the-code-itself)
  - [Reachability — exploitability through the three consumers](#reachability--exploitability-through-the-three-consumers)
  - [Basis in published standards](#basis-in-published-standards)
  - [Governing rules](#governing-rules)
- [**Findings**](#findings) — all 18, with severity, reachability and CWE
  - [Provenance and currency](#provenance-and-currency)
  - [A note on the shape of 000, 001 and 002](#a-note-on-the-shape-of-000-001-and-002)
- [Applicability summary](#applicability-summary)
  - [Revisions assessed](#revisions-assessed)
  - [The invariants these conclusions rest on](#the-invariants-these-conclusions-rest-on)
- [Reproduction](#reproduction)
- [Test conventions](#test-conventions)
- [Status](#status)
- [Standards referenced](#standards-referenced)

## Scope and method

**Reviewed.** Composite construction and domain separation; verification logic; key
generation, seed expansion and key import; serialization and malformed-input handling;
randomness sourcing; secret lifetime; test and known-answer-vector coverage. For `kem/`:
the ML-KEM FO transform, hybrid combiner, and caller obligations.

**Inherited primitives.** `sign/ed25519`, `sign/mldsa`, `sign/slhdsa`, `sign/internal` and the
whole `kem/` cryptographic core were diffed against upstream Cloudflare CIRCL. Their arithmetic
and sign/verify (encapsulate/decapsulate) paths are unmodified apart from import-path renames;
fork changes are additive APIs, added tests, or *stricter* validation. Upstream known-answer
vectors are retained in full. They are treated as upstream-equivalent and are not re-analysed,
except where a finding below explicitly concerns inherited behaviour — those are marked
**upstream-inherited**, and each states whether upstream has since fixed it — in which case the
action is to cherry-pick rather than to report.

**Consumers.** Applicability was assessed against the three intended consumers, by tracing
every call site into `sign/` and `kem/`:

- [`quantum-coin-go`](https://github.com/quantumcoinproject/quantum-coin-go) — the blockchain node
- [`quantum-coin-js-sdk`](https://github.com/quantumcoinproject/quantum-coin-js-sdk) — the WASM/JavaScript SDK
- [`quantumcoin.js`](https://github.com/quantumcoinproject/quantumcoin.js) — the ethers-style wrapper over the SDK
- [`quantum-coin-wallet-desktop`](https://github.com/quantumcoinproject/quantum-coin-wallet-desktop) — the Electron desktop wallet; an **indirect** consumer, reaching the library through `quantumcoin.js` (`quantumcoin ^8.0.3`)

The desktop wallet is included because it exercises paths the SDKs merely expose. In particular
it offers **restore-from-seed and restore-from-seed-words**, so a base seed can originate from a
user rather than from a CSPRNG — which is what makes FINDING-000 reachable. Where a finding's
reachability through the desktop wallet is identical to `quantumcoin.js`, it is not called out
separately.

The two JavaScript packages are **QuantumCoin-specific SDKs, not general-purpose cryptographic
libraries**. Their threat model is bounded accordingly; using the embedded circl WASM as a
general signing library is unsupported, and the assessments here do not extend to that.

**Verification standard.** Every finding below was confirmed by executing code, not by
inspection alone. Findings that could not be reproduced were discarded and are not listed.

## How to read this

**This index lists open findings only.** Anything verified fixed is removed rather than carried
as history; see [Provenance and currency](#provenance-and-currency) for what was resolved.

**Nothing here describes an active compromise.** No listed finding permits forgery under an
honest key, recovery of private key material, or theft of funds in any consumer. These are
hardening, robustness and caller-obligation items, none rated above Medium.

## Methodology

Ratings are assigned on two independent axes so that a genuine library defect is neither
overstated nor dismissed because no consumer happens to reach it.

### Severity — the defect in the code itself

Judged **independently** of whether any consumer can reach it, and without assuming any
particular caller. This is not an implication that the library is offered for general use — see
the [intended-scope note](README.md#intended-scope--important) — it is simply what makes the
rating reproducible.

| Level | Criterion |
|---|---|
| **Critical** | Breaks a core security notion (EUF-CMA / SUF-CMA / IND-CCA2) or permits key recovery, at a practical work factor. |
| **High** | Breaks a core notion under constrained but realistic conditions, or permits forgery given a plausible caller configuration. |
| **Medium** | Violates a hardening notion *beyond* unforgeability (BUFF properties, non-separability, domain separation), **or** silently voids a security control the design depends on, **or** becomes a forgery under a plausible parameter change. |
| **Low** | No path to forgery or key recovery under any examined configuration: API robustness, availability, secret lifetime, or reduced margin. |
| **Informational** | Documentation, naming, conformance or structural observation with no security effect under any examined configuration. |

### Reachability — exploitability through the three consumers

| Level | Criterion |
|---|---|
| **Reachable** | An exploit path exists through a supported consumer API. |
| **Partially reachable** | Triggerable through some supported paths, but the consequence is bounded (e.g. availability only) or protected paths dominate. |
| **Not reachable** | No supported consumer path triggers it. The preventing property is named in the finding. |
| **n/a** | Process, assurance or defence-in-depth item with no runtime attack path. |

### Basis in published standards

Stated plainly so the provenance of each part is not overclaimed:

**The two-axis structure is standard risk-assessment practice**, not a local invention.
[SP 800-30r1] (*Guide for Conducting Risk Assessments*) and the [OWASP Risk Rating
Methodology][owasp-rr] both assess likelihood and impact on separate scales before combining;
ISO/IEC 27005 does the same with likelihood and consequence; and [CVSS v4.0][cvss4] separates
Exploitability from Impact metric groups within its Base score.

**The reachability axis corresponds to a real standard: VEX** (Vulnerability Exploitability
eXchange), originated by CISA and encoded in [OASIS CSAF 2.0][csaf] and [OpenVEX][openvex]. VEX
exists precisely to record that a weakness present in a component is not exploitable in a given
product. The `not_affected` justification codes map onto findings here:

| VEX justification | Findings |
|---|---|
| `vulnerable_code_not_in_execute_path` | 005, 014, 015, 016 — the API is never called by any consumer |
| `vulnerable_code_cannot_be_controlled_by_adversary` | 004 — signing randomness is CSPRNG-only |
| `inline_mitigations_already_exist` | 001, 002, 003 (keystore path), 013 — whole-key hashing, enforced message length, MAC-before-import, HKDF over the KEM secret |

Findings marked *Reachable* or *Partially reachable* correspond to VEX `affected`.

**Classification uses [CWE]** (MITRE); the relevant category view is [CWE-310],
*Cryptographic Issues*.

**What is *not* standardized: the severity level definitions.** No NIST, ISO or IETF document
defines severity levels for cryptographic weaknesses. The table above is a house scale, stated
explicitly so it is reproducible — it carries no external authority. The nearest standardized
crypto-specific rating measures something different: Common Criteria **AVA_VAN attack potential**
(ISO/IEC 15408-3, with the JIL smartcard interpretation, [commoncriteriaportal.org][ccp]) rates
*attack difficulty* from Elapsed Time, Expertise, Knowledge of TOE, Window of Opportunity and
Equipment. [SP 800-131A r2] gives algorithm lifecycle status (acceptable / deprecated /
disallowed / legacy-use), also not severity.

This is why governing rule 2 exists: where a house label and a formal cryptographic statement
appear to conflict, the formal statement governs.

### Governing rules

1. **Severity is never adjusted for reachability.** The two are independent; the pair is the
   triage state. This rule exists because the earlier reviews this index absorbs showed
   measurable drift without it — including two review lenses rating the same finding
   "high/critical" and "info/low".
2. **Formal statements outrank labels.** A severity label is a triage aid. The authoritative
   content of a finding is the security notion violated plus the work factor. Where a label and
   the formal statement appear to conflict, the formal statement governs.
3. **CWE is classification, not severity.** Where no CWE fits, the finding is left unclassified
   rather than forced into a poor match.

## Findings

| ID | Title | Severity | Reachability | CWE | Tests |
|:---|:---|:---|:---|:---|:---|
| [000](./audit/FINDING-000-seed-expander-entropy.md) | Seed expander discards a third of its 96-byte input | Medium | Reachable | [CWE-1068] | yes |
| [001](./audit/FINDING-001-key-substitution.md) | Composite public key not bound into component signed inputs | Medium | Not reachable | [CWE-347] | yes |
| [002](./audit/FINDING-002-cross-mode-separation.md) | Signing mode not bound into every component's signed input | Medium | Not reachable | [CWE-345] | yes |
| [003](#finding-003) | SLH-DSA private-key half not validated on import | Medium | Partially reachable | [CWE-354] | no |
| [004](#finding-004) | Silent short read in the compact-mode ML-DSA randomizer | Low | Not reachable | [CWE-252] | no |
| [005](#finding-005) | Nil randomness reader panics in `Sign` | Low | Not reachable | [CWE-476] | no |
| [006](#finding-006) | No known-answer vectors pin the composite signature construction | Low | n/a | — | n/a |
| [007](#finding-007) | Scheme 2 and scheme 4 key/signature lengths collide | Informational | Not reachable | [CWE-843] | no |
| [008](#finding-008) | Compact mode is a 2-of-3 hybrid; no SLH-DSA signature is verified | Medium | Reachable (by design) | [CWE-757] | no |
| [009](#finding-009) | `hybrideds` signs via non-FIPS internal entry points | Low | Reachable | [CWE-1240] | no |
| [010](#finding-010) | Secret intermediates are not zeroized (`sign` and `kem`) | Low | n/a | [CWE-226] | no |
| [012](#finding-012) | Ed25519 verification does not reject small-order public keys | Informational | Not reachable | [CWE-1240] | no |
| [013](#finding-013) | Hybrid KEM shared secret is a naked concatenation | Low | Not reachable | [CWE-325] | no |
| [014](#finding-014) | Deterministic encapsulation permits seed-reuse correlation | Low | Not reachable | [CWE-323] | no |
| [015](#finding-015) | KEM private-key import is not a validating boundary | Low | Not reachable | [CWE-20] | no |
| [016](#finding-016) | Panic-based package-level KEM APIs | Low | Not reachable | [CWE-248] | no |
| [017](#finding-017) | Distinguishable failure modes between hybrid KEM legs | Informational | Not reachable | [CWE-203] | no |
| [018](#finding-018) | ML-KEM public-key unmarshal is CPU-amplifying | Low | Partially reachable | [CWE-405] | no |

Findings 000–002 have dedicated write-ups. Findings 003–018 are recorded inline below in full.

### Provenance and currency

This index consolidates three earlier review passes (two model families across cryptographer /
implementation-safety / offensive lenses) with the work recorded here. Every absorbed finding
was **re-verified by execution against the current tree**, not carried over on trust.

**Fixed findings are not listed.** Three items raised by the earlier passes are resolved — two
were already fixed when re-verified, and one (the ML-DSA OIDs, below) was fixed during this pass
by cherry-picking upstream. None was ever reachable from any consumer, so all were removed rather
than recorded: the code and its tests are the durable record.

Upstream CIRCL fixes `39afa0b` (slhdsa full reads, #634), `79a0516` (slhdsa prehash range,
#647) and `651c11b` (ed25519 trailing data, #643) are merged; FINDING-004's scope shrank
accordingly, and three items previously flagged as *missing* upstream hardening are resolved.

A fourth, `5cdb72f` "Correct OIDs for ML-DSA" (2025-08-11), was found missing during this pass
and has since been cherry-picked — the ML-DSA scheme OIDs had omitted the `sigAlgs` arc,
returning `2.16.840.1.101.3.4.17/18/19` instead of the registered
`2.16.840.1.101.3.4.3.17/18/19` ([RFC 9882] §2). It is not listed as a finding because it is
fixed. Divergence from upstream was re-checked against a local `cloudflare/circl` checkout at
`df9fbea`; no other outstanding upstream correction was found in the audited packages.

One earlier observation is deliberately **not** carried forward: comment-only nits in the Kyber
field arithmetic, where the code was confirmed correct. That is a cosmetic item, not a finding.

Last re-verified by execution against commit `87e30cb`.

### A note on the shape of 000, 001 and 002

The first three findings are variations on one root cause: **too little is bound into what each
component signs.**

- **000** — the *seed* is under-bound: a third of the base seed never reaches the derivation.
- **001** — the *composite public key* is not bound, so the verification predicate factorises
  across components and a component signature can be transplanted between keys.
- **002** — the *signing mode* is not bound, so separation between compact and full mode rests
  on a payload-length coincidence rather than on domain separation.

001 and 002 share a remediation exactly: a single `bind` value covering the scheme identifier
**and** the full composite public key, absorbed into every component's signed input, discharges
both. They should be fixed together to avoid two consecutive wire-format breaks.

---

### FINDING-000 — Seed expander discards a third of its 96-byte input

**Severity:** Medium **Reachability:** Reachable **CWE:** [CWE-1068]
**Full write-up: [FINDING-000-seed-expander-entropy.md](./audit/FINDING-000-seed-expander-entropy.md)**

`hybrideds.ExpandSeed` takes a 96-byte base seed but only 64 bytes reach the construction; the
32 bytes at odd indices below 64 are discarded. Confirmed by execution: flipping each of the 96
input positions in turn changes the output for exactly 64 and leaves it unchanged for exactly 32.

**Security-strength requirement met, with no headroom above it.** Assuming a uniform base seed, the XOF
branch receives 256 bits (feeding Ed25519 *and* all SPHINCS+ seed material) and the Dilithium2
pass-through receives an independent 256 bits. Every component therefore meets the target
security strength of its parameter set, per [SP 800-133r2] §5.1 read with the security-strength
definition in [SP 800-57 Pt.1 r5] §5.6.1. But SPHINCS+-SHAKE-256f-simple is PQC **category 5** —
a 256-bit target — and receives exactly 256 bits, so it sits on the threshold with nothing in
reserve.

**No FIPS conformance claim is made, and none is available.** `hybrideds` implements the Round 3
draft algorithms [Dilithium2] and [SPHINCS+-SHAKE-256f-simple], not [FIPS 204] ML-DSA-44 and
[FIPS 205] SLH-DSA-SHAKE-256f — the Go identifiers `mldsa44` and `slhdsa` are reused as *code*
via their `Internal` / `NoContext` entry points, which reproduce the pre-final wire format. This
is also not a [CMVP]-validated module.

**The severity driver is non-injectivity, not the entropy accounting.** Because the seed-words
mapping is exactly positional — word *k* encodes bytes `2k` and `2k+1` — and the absorbed bytes
are the even indices below 64, **each of the first 32 words carries one absorbed byte and one
discarded byte**. For any such word, 256 alternative words share its first byte, so

```
256^32 = 2^256 distinct 48-word phrases open the identical wallet, silently.
```

These are not abstract preimages: they are phrases a user could write down. A seed phrase is
routinely treated as an identity or credential rather than mere key material, and this breaks
that: deduplication and "have I seen this seed" logic silently fails; proof-of-ownership and
custody-dispute reasoning breaks, since a holder of phrase Y controls the wallet registered under
phrase X with nothing able to distinguish them; and backup-verification tooling cannot detect that
a recorded phrase differs from the original.

The stated precondition ("a KDF with ≥ 256 bits of min-entropy") is also **necessary but not
sufficient** — entropy in the discarded positions contributes exactly zero, so the requirement is
positional, not aggregate.

**Reachable — via restore-from-seed.** Newly generated wallets are safe: their base seeds come
from a CSPRNG, whose uniformity satisfies the positional requirement automatically. But the
**restore** path accepts a base seed the library did not generate. Traced end to end in the
desktop wallet:

```
restore-from-seed / seed-words UI
  → walletCreateNewWalletFromSeed(seedArray)      src/lib/wallet.ts
  → IPC "WalletFromSeed"                          dist/electron/ipc/crypto.js
  → quantumcoin.js  Wallet.fromSeed(seed)         src/wallet/wallet.js:631
  → qcsdk.openWalletFromSeed(seed)                (96-byte seed ⇒ hybrideds)
  → hybrideds.ExpandSeed                          ← a third of it is discarded
```

`Wallet.fromSeed` validates only that the seed is 64, 72 or 96 bytes. Nothing anywhere in the
chain checks how that entropy is *distributed*, and the library's own documented contract does
not require it to be. A seed originating from a legacy wallet, another implementation, or any
generator unaware of the positional requirement can therefore reach `ExpandSeed` with materially
less than 256 bits landing on the absorbed positions — degrading the Ed25519 and SPHINCS+ keys
together, since both derive from that one branch.

**Why Medium.** The entropy analysis and the injectivity analysis pull in different directions,
so the boundaries are worth stating:

- **Not High.** There is no attacker-*initiated* path. Deriving a colliding phrase requires the
  absorbed bytes — i.e. the key — and an attacker who supplies a victim a seed already knows it.
  Every generator in the ecosystem is a CSPRNG, so no deployed seed is degenerate.
- **Not Low.** "Reduced margin" does not cover a 2^256-to-1 phrase→wallet map that no layer
  surfaces. That silently voids seed-uniqueness assumptions in surrounding systems, which is the
  Medium criterion.
- **Medium + Reachable is coherent, not contradictory.** *Reachable* says a supported API accepts
  the input; *Medium* says the consequence stops short of forgery or key recovery. This is the
  clearest illustration in the audit of the two axes being genuinely independent.

---

### FINDING-001 — Composite public key not bound into component signed inputs

**Severity:** Medium **Reachability:** Not reachable **CWE:** [CWE-347] (parent [CWE-345])
**Full write-up: [FINDING-001-key-substitution.md](./audit/FINDING-001-key-substitution.md)**

No component signs anything derived from the *composite* public key, so the verification
predicate factorises over the three components. An adversary who has only observed a published
signature can build a composite key that keeps the victim's Ed25519 public key, substitutes
adversary-generated ML-DSA and SLH-DSA keys, and assemble a signature on the same message that
verifies under it.

This does **not** break EUF-CMA/SUF-CMA, any component primitive, or key confidentiality. The
substituted key is *parasitic*: the adversary never learns the Ed25519 private key and so cannot
sign anything the victim has not already signed. Formally it is a failure of non-separability
for combined signature schemes; the remedy is the BUFF transform.

Affects all three schemes. `hybrideds` compact mode is partially resistant — it binds the
SLH-DSA public key into the signed hash, and that half correspondingly cannot be substituted,
which is positive evidence that the proposed fix works.

Rated Medium as a beyond-unforgeability hardening failure, the same class as FINDING-002.
**Not reachable** because all three consumers derive identity from a hash of the *complete*
composite public key, so a substituted key is a different address belonging to the adversary.

---

### FINDING-002 — Signing mode not bound into every component's signed input

**Severity:** Medium **Reachability:** Not reachable **CWE:** [CWE-345]
**Full write-up: [FINDING-002-cross-mode-separation.md](./audit/FINDING-002-cross-mode-separation.md)**

`hybrideds` and `hybridedmldsaslhdsa` each expose compact and full signing modes over a single
key pair. In `hybrideds` no component carries a mode domain separator: the two modes are
distinguished only by the **length** of the signed payload — 32 bytes full, 64 compact. That is
sufficient today and enforced fail-closed inside both `Sign` and `SignCompact`, but it is an
arithmetic accident between two constants chosen for unrelated reasons. Two individually
reasonable parameter changes — admitting 64-byte messages, or shortening the compact digest to
32 bytes — each collapse the payload images together and yield an existential forgery under
chosen-message attack.

The per-signature random nonce in the compact payload is **not** a mitigation: the verifier
reads it out of the signature, so in a forgery the adversary supplies it.

**Not reachable**: every message reaching the library is a 32-byte digest and the library
enforces that length in both modes; additionally no consumer invokes `hybrideds` full-mode
signing on any path, so the signing oracle the attack requires does not exist.

---

<a id="finding-003"></a>
### FINDING-003 — SLH-DSA private-key half is not validated on import

**Severity:** Medium **Reachability:** Partially reachable **CWE:** [CWE-354]
**Affects:** all three hybrid packages, in `checkConsistency`

`UnmarshalPrivateKey` validates that the embedded Ed25519 and ML-DSA public halves match their
private material, but never recomputes the SLH-DSA public root from the SLH-DSA seed. The
in-code comment states an SLH-DSA mismatch is "caught on first Verify" — but in **compact** mode
no SLH-DSA verification ever happens.

Confirmed by execution: flipping one bit of the SLH-DSA `SK.seed` in a marshalled private key
yields a key that (1) imports with **no error**, (2) signs and verifies **indefinitely** in
compact mode, and (3) is **silently unusable** in full mode. A wallet restored from a bit-rotted
or tampered raw key backup transacts normally and discovers the failure only at break-glass time
— precisely when Ed25519 and ML-DSA are assumed broken — with no recovery path. Rated Medium
because it silently voids the control the hybrid design exists to provide.

**Partially reachable.** The encrypted-keystore path is protected: the MAC is verified *before*
decryption, and V5 keystores regenerate from the pre-expansion seed rather than importing.
Exposed paths accept a **raw** private key with only a length check: `personal_importRawKey` /
`clef_importRawKey`, the WASM `PublicKeyFromPrivateKey` and `circl.*.sign` entry points, the
SDK's `sign()` / `signRawTransaction()`, and `deserializeWallet`. Accidental corruption is at
least as plausible as deliberate tampering.

**Note for any fix.** Recomputing the SLH-DSA root costs **5.4 ms** (SHAKE-256f) against ~19 µs
for an Ed25519 signature. `quantum-coin-go` calls `UnmarshalPrivateKey` on *every* signature, so
adding the check there would slow the default compact-signing consensus path by roughly an order
of magnitude. Expose it separately (e.g. a strict import variant) so it is paid at genuine import
boundaries only.

---

<a id="finding-004"></a>
### FINDING-004 — Silent short read in the compact-mode ML-DSA randomizer

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-252] (consequence [CWE-331])
**Affects:** `sign/mldsa/mldsa44` and `mldsa87` (`Sign`), reachable only via `hybridedmldsaslhdsa.SignCompact`
**Largely fixed upstream** — scope reduced

Upstream `39afa0b` changed `slhdsa.readRandom` to `io.ReadFull`, and because SLH-DSA reads last
in almost every path, that single change closes key generation and full-mode signing across all
three schemes. Re-verified by execution:

| Path | Status |
|---|---|
| `GenerateKey` — all three schemes | **Fixed** — a 159-byte reader (160 needed) returns `unexpected EOF` |
| `hybrideds.Sign` | Covered — the SLH-DSA read fails first |
| `hybrideds.SignCompact` | Covered — explicit `bytesRead` checks |
| `hybridedmldsaslhdsa.Sign`, `hybridedmldsaslhdsa5.Sign` | Covered — the SLH-DSA read fails first |
| **`hybridedmldsaslhdsa.SignCompact`** | **Still present** |

`mldsa44.Sign` / `mldsa87.Sign` still call `random.Read(rnd[:])` once and discard the count.
Compact mode draws no SLH-DSA randomness, so nothing catches it: confirmed, `SignCompact` with a
10-byte reader returns a signature and **no error**, byte-identical to the all-zeros 32-byte
reader — the missing 22 bytes were silently zero-filled. ML-DSA signing is hedged rather than
nonce-fragile, so the effect is degradation toward deterministic signing, not key leakage.

**Not reachable**: all eight reader-taking call sites in `quantum-coin-go` and every one in the
WASM layer pass the literal `crypto/rand.Reader`.

---

<a id="finding-005"></a>
### FINDING-005 — Nil randomness reader panics in `Sign`

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-476]

`Sign(priv, nil, msg)` panics with a nil-pointer dereference, while `GenerateKey(nil)` works and
falls back to `crypto/rand`. Confirmed by execution in both `hybridedmldsaslhdsa` and
`hybrideds`. `ed25519` and `slhdsa` both default a nil reader to `crypto/rand`; the ML-DSA
signing entry points are the outlier.

**Not reachable**: no consumer call site passes `nil` — the reader argument is a
compile-time-fixed `crypto/rand.Reader` everywhere.

---

<a id="finding-006"></a>
### FINDING-006 — No known-answer vectors pin the composite signature construction

**Severity:** Low **Reachability:** n/a **CWE:** none applies

Every signing test in the hybrid packages is a self-round-trip. No fixed vector pins the
byte-level construction, so changing a context byte, reordering components, or altering the
compact-mode message composition would break wire compatibility with deployed nodes **without a
single test failing**. The component packages are well covered — ML-DSA and SLH-DSA retain their
full upstream ACVP vector sets — so the gap is specific to the composite layer.

This is the main risk multiplier for any future change. The shared remediation for 001 and 002
*is* a wire-format change; vectors should land before or with it.

---

<a id="finding-007"></a>
### FINDING-007 — Scheme 2 and scheme 4 lengths collide

**Severity:** Informational **Reachability:** Not reachable **CWE:** [CWE-843]

The two schemes have byte-identical public key (1408), private key (4064) and full signature
(52374) sizes, and identical component layouts. Within this library that is safe: dispatch is by
an explicit scheme-ID byte, each scheme re-checks that byte in its own `Verify`, and a duplicate
ID would be a compile error. A key minted for one package structurally fits the other, but
verification *fails* on mismatch because the ML-DSA/SLH-DSA contexts differ — this is not a
forgery path.

It is recorded because the schemes are **not** interchangeable — different seed expander,
different ML-DSA domain separation, different scheme IDs — and a private key carries no scheme
tag. `quantum-coin-go`'s `cryptobase.GetSigAlgForPrivateKey` dispatches on length alone and so
resolves the shared 4064-byte length to `hybrideds`. Any future consumer inferring a scheme from
a *length* rather than the ID byte would be making an unsound inference.

---

<a id="finding-008"></a>
### FINDING-008 — Compact mode is a 2-of-3 hybrid; no SLH-DSA signature is verified

**Severity:** Medium **Reachability:** Reachable (by design) **CWE:** [CWE-757]
**Affects:** `hybrideds` (ID 1), `hybridedmldsaslhdsa` (ID 3)

In compact verifiers the SLH-DSA public key is folded into a hash or context, but **no SLH-DSA
signature exists or is checked**. Compact security therefore rests entirely on Ed25519 +
ML-DSA — post-quantum security on ML-DSA alone, at NIST category 2 for both compact schemes. The
hash-based break-glass layer provides **zero live protection** for any balance ever authorized in
compact mode.

This is documented, deliberate design rather than an implementation defect, and the code states
the caller obligation explicitly. It is recorded because the obligation is safety-critical and
sits outside the library: if a node accepts compact and full signatures interchangeably for the
same account, the effective security of that account is the weaker mode. Rated Medium because the
consequence is loss of the guarantee the hybrid exists to provide.

**Reachable by design.** `quantum-coin-go` gates accepted scheme IDs by block regime
(`IsSignatureTypeAllowedForTxn`) and pins ID 1 for consensus packets, which is the intended
mitigation; compact remains the default transaction mode. The residual obligation — pin an
acceptable scheme ID *per account*, and ideally commit it into address derivation so compact and
full are not fungible — is not currently discharged and is the recommended hardening.

---

<a id="finding-009"></a>
### FINDING-009 — `hybrideds` signs via non-FIPS internal entry points

**Severity:** Low **Reachability:** Reachable **CWE:** [CWE-1240]
**Affects:** `mldsa44.SignNoContext` / `VerifyNoContext`, `slhdsa.Sign*NoContext`, used by `hybrideds`

Schemes 1–2 sign the raw message through entry points that bypass the [FIPS 204] §5.2
`M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` framing and the [FIPS 205] §10.2 prefix — i.e. the *internal*
functions those standards reserve for testing. This is deliberate and load-bearing for wire
compatibility with the pre-standardization implementation, and is the mechanism by which the
package realizes [Dilithium2] and [SPHINCS+-SHAKE-256f-simple] rather than their finalized
successors (see FINDING-000).

The finding is that these are **exported, production-reachable functions whose names do not
signal their status**. A caller reaching for `mldsa44.SignNoContext` gets non-conforming,
non-interoperable signatures with no domain separation, and nothing in the name says so. No
forgery path follows; the issue is API safety and conformance clarity.

Recommended: rename or document the `*NoContext` family to signal non-FIPS/internal status, and
treat schemes 1–2 as legacy verification-only in node policy.

---

<a id="finding-010"></a>
### FINDING-010 — Secret intermediates are not zeroized

**Severity:** Low **Reachability:** n/a **CWE:** [CWE-226]
**Affects:** hybrid `getPrivateKeys` (`sk1`/`sk2`/`sk3`), Ed25519 and ML-DSA key-derivation buffers, `kem/mlkem/*`, `kem/hybrid/xkem.go`

Raw seed and secret-key intermediates are left to the garbage collector. Confirmed: the hybrid
`getPrivateKeys` allocates three fresh secret buffers per call — and it is called on *every*
signature — with no deferred wipe. The KEM stack performs no zeroization at all.

Good counter-examples exist in the same tree and should be the template: the seed expanders wipe
their intermediates in a deferred closure, and `slhdsa` calls `state.Clear()`.

This is defence-in-depth with no attack path absent memory disclosure, swap, or a core dump on a
node holding keys — hence **n/a** reachability rather than "not reachable". Note the caveat the
seed expander already documents: Go does not formally guarantee dead-store elimination will
spare such writes, though gc and gccgo retain them inside deferred closures in practice.

---

<a id="finding-012"></a>
### FINDING-012 — Ed25519 verification does not reject small-order public keys

**Severity:** Informational **Reachability:** Not reachable **CWE:** [CWE-1240]
**Upstream-inherited**

`verify` checks `isLessThanOrder(S)` — so signatures are non-malleable — and that the public key
decodes to a valid point, but performs no torsion or small-order check on `A`, and uses
cofactorless verification. Confirmed by inspection of the current `verify` body.

This matches upstream CIRCL **and** Go's `crypto/ed25519`, so it is standard behaviour rather
than a fork defect. Inside the hybrid it is inert: forging requires all three components, and
FINDING-001 notwithstanding, a substituted key yields a different address.

Relevant only if Ed25519 is ever exposed standalone with attacker-registered public keys, or if
batch verification is added — both of which change the analysis and should trigger a re-review.

---

<a id="finding-013"></a>
### FINDING-013 — Hybrid KEM shared secret is a naked concatenation

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-325]
**Affects:** `kem/hybrid/hybrid.go`

`Encapsulate` returns `append(ss1, ss2...)` — the X25519 and ML-KEM shared secrets concatenated,
with no KDF applied. Confirmed by inspection. Deriving usable key material from this is a **hard
caller obligation**: used directly as a symmetric key, the combiner provides no better security
than its components and no binding to the transcript or ciphertexts.

**Not reachable**: `quantum-coin-go` feeds the concatenated secret into a TLS 1.3-style HKDF
schedule with transcript binding in RLPx, and zeroes it after use — which is exactly the correct
discharge of the obligation. The finding stands against the library, whose API invites the
mistake without documenting it as a requirement.

---

<a id="finding-014"></a>
### FINDING-014 — Deterministic encapsulation permits seed-reuse correlation

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-323]
**Affects:** `kem/hybrid/hybrid.go`, `kem/hybrid/xkem.go`

`EncapsulateDeterministically` derives all randomness from a caller-supplied seed. Reusing a seed
against the same recipient yields an identical `(ct, ss)` pair; reusing it across *different*
recipients reuses the X25519 ephemeral key, which is a genuine key-reuse hazard rather than a
mere determinism artefact.

This is inherent to a deterministic API and is the correct behaviour for KAT reproduction; the
finding is that the reuse hazard is not documented at the call site.

**Not reachable**: no consumer calls `EncapsulateDeterministically`; KEM keys in the node are
ephemeral and self-generated per connection.

---

<a id="finding-015"></a>
### FINDING-015 — KEM private-key import is not a validating boundary

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-20]
**Affects:** `kem/mlkem/*/kyber.go`, `kem/hybrid/xkem.go`

Private-key unmarshalling performs length checks but does not fully validate internal
consistency — the analogue of FINDING-003 in the KEM stack. An inconsistent or corrupted key can
be imported and used, failing later and opaquely rather than at the boundary.

**Not reachable**: no consumer imports KEM private keys from untrusted input; node KEM keys are
ephemeral and self-generated.

---

<a id="finding-016"></a>
### FINDING-016 — Panic-based package-level KEM APIs

**Severity:** Low **Reachability:** Not reachable **CWE:** [CWE-248]
**Affects:** `kem/mlkem/*/kyber.go`, `kem/hybrid/*`

The package-level `*To` and `DeriveKeyPair` helpers panic on malformed input instead of returning
errors. In a networked node a panic on attacker-influenceable input is an availability concern,
and the failure mode differs from the error-returning `Scheme()` interface over the same
operations.

**Not reachable**: the node uses the `Scheme()` interface exclusively, which returns errors.

---

<a id="finding-017"></a>
### FINDING-017 — Distinguishable failure modes between hybrid KEM legs

**Severity:** Informational **Reachability:** Not reachable **CWE:** [CWE-203]
**Affects:** `kem/hybrid/xkem.go`

The X25519 leg returns an explicit error on malformed input while ML-KEM fails *implicitly* via
the FO transform's implicit rejection, producing a pseudorandom shared secret rather than an
error. A caller that surfaces the two differently gives an observer a distinguisher for which leg
failed.

No key material is leaked, and implicit rejection is the correct FIPS 203 behaviour. The concern
is only that the combiner surfaces two different failure shapes.

**Not reachable**: the node handles decapsulation failure uniformly.

---

<a id="finding-018"></a>
### FINDING-018 — ML-KEM public-key unmarshal is CPU-amplifying

**Severity:** Low **Reachability:** Partially reachable **CWE:** [CWE-405]
**Affects:** `pke/kyber/kyber768/internal/cpapke.go`

Unmarshalling a public key performs full matrix-`A` expansion — the dominant cost of the
operation — before any use. An attacker who can submit public keys obtains a work asymmetry:
cheap to send, comparatively expensive to parse.

**Partially reachable**: the RLPx handshake parses peer-supplied KEM public keys, so the path is
network-facing, but it is bounded by connection rate limits and the amplification factor is
modest. Mitigation is rate-limiting or deferring expansion until the key is actually used.

---

## Applicability summary

### Revisions assessed

Every "not reachable" verdict is a statement about a specific revision of a specific consumer,
and stops being evidence the moment that consumer changes. The verdicts below were established
by tracing call sites at these exact commits:

| Repository | Commit | Date | Worktree |
|:---|:---|:---|:---|
| `circl` (this repo) | `87e30cbaeeeb7be8199e72a279835d8d8481c5da` | 2026-08-01 | audit additions only |
| `quantum-coin-go` | `8a060985b9badaf69f449ef06baaab4309a57dc2` | 2026-08-01 | clean |
| `quantum-coin-js-sdk` | `b5ec38cb8fcd2dabea830eae236b9b98c934f6d6` | 2026-07-05 | clean |
| `quantumcoin.js` | `b08a794117e04bca01ca608e6c4a78aa2f44da98` | 2026-07-19 | **14 uncommitted changes present** |
| `quantum-coin-wallet-desktop` | `0e2724ee80eb0eec20e98228d8715717b4fcab60` | 2026-07-30 | clean |

The `quantumcoin.js` assessment was made against the working tree at that commit, not the commit
alone; its uncommitted changes were included in what was read. Re-confirm that verdict once they
are committed.

Re-tracing is required whenever a consumer changes any of the invariants listed after the table
below — in particular address derivation, message length, randomness sourcing, scheme-ID policy,
or KEM shared-secret handling.

| Finding | quantum-coin-go | quantum-coin-js-sdk | quantumcoin.js | wallet-desktop |
|:---|:---|:---|:---|:---|
| 000 — seed expander entropy | Not affected¹ | Reachable via seed import¹ | Reachable via seed import¹ | **Reachable — restore-from-seed**¹ |
| 001 — key substitution | Not affected² | Not affected² | Not affected² | Not affected² |
| 002 — cross-mode separation | Not affected³ | Not affected³ | Not affected³ | Not affected³ |
| 003 — SLH-DSA half unvalidated | Reachable via raw-key import⁴ | Reachable via raw-key import⁴ | Reachable via SDK sign paths⁴ | Reachable via SDK sign paths⁴ |
| 004 — compact ML-DSA short read | Not reachable⁵ | Not reachable⁵ | Not reachable⁵ | Not reachable⁵ |
| 005 — nil reader panic | Not reachable⁵ | Not reachable⁵ | Not reachable⁵ | Not reachable⁵ |
| 006 — missing KATs | Migration risk | Migration risk | Migration risk | Migration risk |
| 007 — length collision | No current impact | No current impact | No current impact | No current impact |
| 008 — compact is 2-of-3 | Reachable by design⁶ | Reachable by design⁶ | Reachable by design⁶ | Reachable by design⁶ |
| 009 — non-FIPS entry points | Reachable (schemes 1–2) | Reachable (schemes 1–2) | Via SDK only | Via SDK only |
| 010 — no zeroization | Defence-in-depth | Defence-in-depth | Defence-in-depth | Defence-in-depth |
| 012 — Ed25519 small-order | Not reachable (hybrid combiner) | Not reachable | Not reachable | Not reachable |
| 013 — KEM naked concatenation | Not reachable (RLPx HKDF)⁷ | n/a (no KEM use) | n/a | n/a |
| 014 — deterministic encapsulation | Not reachable (unused API) | n/a | n/a | n/a |
| 015 — KEM key import | Not reachable (ephemeral keys) | n/a | n/a | n/a |
| 016 — panic-based KEM APIs | Not reachable (`Scheme()` iface) | n/a | n/a | n/a |
| 017 — distinguishable KEM failures | Not reachable (uniform handling) | n/a | n/a | n/a |
| 018 — KEM unmarshal cost | Partially reachable (RLPx) | n/a | n/a | n/a |

¹ **Split verdict.** Seeds the library *generates* come from a CSPRNG, whose uniformity satisfies
the positional requirement automatically — so newly created wallets are unaffected, and
`quantum-coin-go` (which has no restore-from-user-seed path into `hybrideds`) is unaffected
entirely. But `openWalletFromSeed` / `Wallet.fromSeed` accept a caller-supplied 96-byte seed and
validate only its length, and the desktop wallet exposes that as restore-from-seed and
restore-from-seed-words. A seed from a legacy wallet, another implementation, or any generator
unaware of the positional requirement can therefore reach `ExpandSeed` with less than 256 bits on
the absorbed positions.
² All three derive every identity from a hash of the **complete** composite public key.
³ Every message is a 32-byte digest, enforced by the library; no consumer invokes `hybrideds`
full-mode signing.
⁴ Encrypted-keystore paths are MAC-authenticated before import; V5 regenerates from seed.
Exposure is limited to raw-key paths, and the impact is loss of break-glass, not key compromise.
⁵ Every call site passes `crypto/rand.Reader`; no consumer passes `nil` or a custom reader.
⁶ Compact mode is the intended default. The node gates scheme IDs by block regime; the
outstanding hardening is per-account pinning.
⁷ The concatenated secret enters a TLS 1.3-style HKDF schedule with transcript binding.

### The invariants these conclusions rest on

Each "not reachable" verdict depends on a property of the **callers**, not of the library. None
is currently checked or stated in `sign/` or `kem/`:

1. Base seeds are uniformly random across every byte position (000) — **holds for wallets the
   library generates, but NOT guaranteed on the restore-from-seed path**; see FINDING-000.
2. Identity is derived from a hash of the complete composite public key, never a component or
   prefix (001).
3. Messages are always exactly 32 bytes, and `CRYPTO_MSG_LENGTH` ≠ the compact digest length (002).
4. Randomness readers are always `crypto/rand.Reader`, never `nil` and never short-reading (004, 005).
5. Scheme selection uses the scheme-ID byte, never a key or signature length (007).
6. An account's acceptable scheme ID is pinned, so compact and full are not fungible (008).
7. The hybrid KEM shared secret is always passed through a KDF before use (013).

That a cryptographic library should not depend on unstated properties of its callers is the
common thread running through this audit.

## Reproduction

```sh
# FINDING-000
go test -run TestExpandSeed ./sign/hybrideds/

# FINDING-001
go test -run TestKeySubstitution ./sign/hybridedmldsaslhdsa/ ./sign/hybridedmldsaslhdsa5/ ./sign/hybrideds/

# FINDING-002
go test -run "TestCrossMode|TestEd25519Component|TestNoCompactMode|TestShrinking" \
  ./sign/hybrideds/ ./sign/hybridedmldsaslhdsa/ ./sign/hybridedmldsaslhdsa5/
```

The hybrid packages contain exhaustive bit-flip tests that exceed Go's default 10-minute
timeout — `go test ./sign/...` needs an explicit `-timeout` (45m is comfortable) or
`sign/hybridedmldsaslhdsa` will report a spurious failure.

Findings 003–018 have no committed tests; each was reproduced with a throwaway harness during
review, and the reproduction is described inline above.

## Test conventions

Where a finding has tests, they are **characterization tests**: they assert the behaviour the
code has *today*, so CI stays green and the finding remains executable rather than prose-only.

They are simultaneously **tripwires**. Fixing the underlying issue makes them fail — that is the
intended signal, not a regression. Each carries a clearly named constant to invert at that point,
plus instructions to rename the test to assert the secure property directly.

FINDING-000's tests are tripwires in a stronger sense: that expander is frozen for wallet
compatibility, so a failure there means the derivation itself changed and every existing seed
phrase would derive a different wallet.

## Status

| | |
|:---|:---|
| Open findings | 18 |
| Highest severity | Medium |
| Requiring emergency action | 0 |
| Enabling forgery, key recovery or fund loss in any consumer | 0 |
| Reachable in consumers | 4 — FINDING-000 (restore-from-seed), 003 (partial), 008 (by design), 009 |
| Partially fixed upstream | 1 — FINDING-004 |
| Verified fixed and removed from this index | 3 — none ever reachable from any consumer |

## Standards referenced

Schemes 1–2 (`hybrideds`) implement pre-standardization Round 3 drafts; schemes 3–5 implement the
finalized FIPS algorithms. Both sets are listed because the audit spans them.

- [Dilithium2] — *CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation*, v3.1, February 2021 — lattice component of schemes 1–2.
- [SPHINCS+-SHAKE-256f-simple] — *SPHINCS+ Submission to the NIST Post-Quantum Project*, v3.1, June 2022 — hash-based component of schemes 1–2.
- [PQC call for proposals][pqc-categories] — *Submission Requirements and Evaluation Criteria for the Post-Quantum Cryptography Standardization Process*, December 2016; §4.A.5 defines security categories 1–5.
- [FIPS 203] — *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM), August 2024.
- [FIPS 204] — *Module-Lattice-Based Digital Signature Standard* (ML-DSA), August 2024 — schemes 3–5. Note it assigns no object identifiers.
- [NIST CSOR][csor] — Computer Security Objects Register, algorithm registration; the authoritative source for NIST algorithm OIDs. The Digital Signature Algorithms section is a JavaScript accordion with no anchor, so cite RFC 9882 §2 for a stable link.
- [RFC 9882] — *Use of the ML-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)*, Standards Track, October 2025; §2 reproduces the CSOR ML-DSA OID assignments verbatim.
- [draft-ietf-lamps-dilithium-certificates][lamps-mldsa] — IETF LAMPS X.509 algorithm identifiers for ML-DSA.
- [FIPS 205] — *Stateless Hash-Based Digital Signature Standard* (SLH-DSA), August 2024 — schemes 3–5.
- [FIPS 202] — *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*, August 2015 — SHAKE256.
- [FIPS 186-5] — *Digital Signature Standard (DSS)*, February 2023; §7.8 covers EdDSA.
- [RFC 8032] — *Edwards-Curve Digital Signature Algorithm (EdDSA)*, January 2017.
- [SP 800-133r2] — *Recommendation for Cryptographic Key Generation*, Rev. 2, June 2020.
- [SP 800-57 Pt.1 r5] — *Recommendation for Key Management: Part 1 – General*, Rev. 5, May 2020; §5.6.1 defines security strength.
- [SP 800-90A r1] — *Recommendation for Random Number Generation Using DRBGs*, Rev. 1, June 2015.
- [SP 800-90B] — *Recommendation for the Entropy Sources Used for Random Bit Generation*, January 2018; §3.1 defines min-entropy.
- [CWE] — MITRE Common Weakness Enumeration, used for classification only; category view [CWE-310] covers cryptographic issues.

**Risk-assessment and disclosure frameworks** (basis for the methodology above)

- [SP 800-30r1] — *Guide for Conducting Risk Assessments*, Rev. 1, September 2012 — separate likelihood and impact scales.
- [OWASP Risk Rating Methodology][owasp-rr] — likelihood × impact with explicit factors.
- [CVSS v4.0][cvss4] — separates Exploitability and Impact metric groups.
- [OASIS CSAF 2.0][csaf] and [OpenVEX][openvex] — VEX; the standardized form of the reachability axis.
- [SP 800-131A r2] — algorithm lifecycle status (acceptable / deprecated / disallowed / legacy-use).
- [Common Criteria portal][ccp] — ISO/IEC 15408-3 AVA_VAN attack potential; the nearest standardized crypto-specific difficulty rating.
- [CMVP] — NIST Cryptographic Module Validation Program. **This library is not a validated module and no approved-mode claim is made.**

[Dilithium2]: https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
[SPHINCS+-SHAKE-256f-simple]: https://sphincs.org/data/sphincs+-r3.1-specification.pdf
[pqc-categories]: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf
[SP 800-133r2]: https://doi.org/10.6028/NIST.SP.800-133r2
[SP 800-57 Pt.1 r5]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
[SP 800-90A r1]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90B]: https://doi.org/10.6028/NIST.SP.800-90B
[FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
[FIPS 186-5]: https://doi.org/10.6028/NIST.FIPS.186-5
[FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
[FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[CWE]: https://cwe.mitre.org/
[CMVP]: https://csrc.nist.gov/projects/cryptographic-module-validation-program
[SP 800-30r1]: https://doi.org/10.6028/NIST.SP.800-30r1
[SP 800-131A r2]: https://doi.org/10.6028/NIST.SP.800-131Ar2
[owasp-rr]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
[cvss4]: https://www.first.org/cvss/v4.0/specification-document
[csaf]: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
[openvex]: https://github.com/openvex/spec
[ccp]: https://www.commoncriteriaportal.org/
[CWE-20]: https://cwe.mitre.org/data/definitions/20.html
[CWE-203]: https://cwe.mitre.org/data/definitions/203.html
[CWE-226]: https://cwe.mitre.org/data/definitions/226.html
[CWE-248]: https://cwe.mitre.org/data/definitions/248.html
[CWE-252]: https://cwe.mitre.org/data/definitions/252.html
[CWE-310]: https://cwe.mitre.org/data/definitions/310.html
[CWE-323]: https://cwe.mitre.org/data/definitions/323.html
[CWE-325]: https://cwe.mitre.org/data/definitions/325.html
[CWE-331]: https://cwe.mitre.org/data/definitions/331.html
[CWE-345]: https://cwe.mitre.org/data/definitions/345.html
[CWE-347]: https://cwe.mitre.org/data/definitions/347.html
[CWE-354]: https://cwe.mitre.org/data/definitions/354.html
[CWE-405]: https://cwe.mitre.org/data/definitions/405.html
[CWE-476]: https://cwe.mitre.org/data/definitions/476.html
[CWE-757]: https://cwe.mitre.org/data/definitions/757.html
[CWE-843]: https://cwe.mitre.org/data/definitions/843.html
[CWE-1068]: https://cwe.mitre.org/data/definitions/1068.html
[CWE-1240]: https://cwe.mitre.org/data/definitions/1240.html
[csor]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
[lamps-mldsa]: https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/
[RFC 9882]: https://www.rfc-editor.org/rfc/rfc9882.html#section-2
[lamps-asn]: https://github.com/lamps-wg/dilithium-certificates/blob/main/X509-ML-DSA-2025.asn
[RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410.html#section-3
