# FINDING-001: composite public key is not bound into component signed inputs

| | |
|---|---|
| **Status** | Open — documented, not fixed |
| **Affects** | `sign/hybridedmldsaslhdsa`, `sign/hybridedmldsaslhdsa5`, `sign/hybrideds` |
| **Class** | Separability of a combined signature scheme; failure of exclusive ownership (DSKS family) |
| **CWE** | [CWE-347] (Improper Verification of Cryptographic Signature); parent [CWE-345]. Verification is spec-correct — the gap is the absent key binding. |
| **Severity** | **Medium** — violates a hardening notion *beyond* unforgeability. Rated per the scale in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md#methodology). See [note on the rating](#note-on-the-severity-rating). |
| **Reachability** | **Not reachable** — every consumer derives identity from a hash of the complete composite public key. |
| **Impact on current consumers** | **None.** See [Applicability](#applicability). |
| **EUF-CMA / SUF-CMA** | **Unaffected.** See [What is and is not broken](#what-is-and-is-not-broken). |
| **Reproduction** | `keysubstitution_test.go` in each affected package |

---

## Summary

The three hybrid schemes construct a composite signature by concatenating independent
component signatures. The input signed by each component does not depend on the **composite**
public key. As a consequence a component signature can be separated from one composite
signature and transplanted into a valid composite signature under a *different* composite
public key.

Concretely: an adversary who has only **observed** a published signature can construct a
composite public key that retains the victim's Ed25519 public key, substitutes
adversary-generated ML-DSA and SLH-DSA keys, and assemble a signature on the *same message*
that `Verify` accepts under that new key — without ever obtaining the victim's Ed25519
private key.

**This is not a forgery under the victim's key, and it is not exploitable in any of the
three intended consumers.** It is a deviation from a hardening property that combined
signature schemes are expected to provide, and it matters because the property is currently
supplied by the callers rather than by the scheme.

## Note on the severity rating

This finding was initially recorded as Low. It is rated **Medium** under the methodology
declared in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md#methodology), which places any violation of a
beyond-unforgeability hardening notion at that level — the same class as FINDING-002, which was
already Medium. The re-rating resolves an inconsistency between two findings of identical class;
**no technical claim has changed**, and the "not exploitable in any consumer" conclusion below
stands unaltered.

Per the precedence rule in the methodology, the label is a triage aid: the authoritative content
of this finding is the security notion violated and the bounded adversarial capability set out
below.

## What is and is not broken

**Not broken.** All of the following continue to hold and are unaffected by this finding:

- **EUF-CMA and SUF-CMA of the composite scheme** under an honestly generated key. The
  adversary cannot produce any new valid `(m*, σ*)` under the victim's public key `pk`.
- **Security of every component primitive.** Ed25519, ML-DSA-44/87 and SLH-DSA are used as
  specified; nothing here is an attack on them.
- **Key privacy.** No private key material is recovered or weakened.
- **Verification soundness.** `Verify` correctly requires all present components to verify;
  there is no short-circuit or partial acceptance.

**Broken.** The scheme is **separable**, and correspondingly does not provide **exclusive
ownership**: a `(message, signature)` pair is not bound to a unique public key.

### Why, mathematically

Write the composite scheme with `pk = (pk₁, pk₂, pk₃)` and let `μᵢ` denote the input that
component *i* actually signs. Verification is the conjunction

```
Verify(pk, m, σ)  =  ⋀ᵢ  Verifyᵢ(pkᵢ, μᵢ(m), σᵢ)
```

In the current construction each `μᵢ` is a function of `m` (and, at most, of a constant
scheme identifier or of `pk₃`) — **never of the whole `pk`**. The conjunction therefore
*factorises*: it contains no term coupling `(pk₁, σ₁)` to `(pk₂, σ₂)` or `(pk₃, σ₃)`.

Any triple of independently satisfying pairs `(pkᵢ, σᵢ)` consequently satisfies the whole
predicate, regardless of provenance. That is the entire finding; everything below is a
consequence.

The remedy is to destroy the factorisation by making every `μᵢ` depend on all of `pk` — the
BUFF transform, `μᵢ(m) = (m, ctxᵢ ‖ H(pk₁‖pk₂‖pk₃))`. Then altering `pk₂` changes `μ₁` and
`μ₃`, invalidating `σ₁` and `σ₃`.

### Precise adversarial capability, and its bounds

Let the adversary `A` observe `(pk, m, σ)` where `σ = (σ₁, σ₂, σ₃)` and `pk = (pk₁, pk₂, pk₃)`.
`A` samples `(pk₂', sk₂')` and `(pk₃', sk₃')` honestly, sets

```
pk' = (pk₁, pk₂', pk₃')        σ' = (σ₁, σ₂', σ₃'),  σᵢ' = Signᵢ(skᵢ', μᵢ(m))
```

and obtains `Verify(pk', m, σ') = 1` with `pk' ≠ pk` and `σ' ≠ σ`.

The capability is bounded in three ways that materially limit impact, and auditors should
weigh them:

1. **`pk'` is parasitic, not a usable identity.** `A` does not learn `sk₁`. Hence `A` cannot
   compute `Sign(sk', m*)` for any `m*` outside the set `Q` of messages the victim has
   already signed. `pk'` can only ever "sign" messages in `Q`, reusing the victim's own `σ₁`.
2. **The victim's key is untouched.** `A` gains no advantage against `Verify(pk, ·, ·)`.
3. **`m` is not adversarially chosen.** `A` is restricted to messages in `Q`.

Relative to the standard notions: because `A` re-randomises the components it controls,
`σ' ≠ σ`, so this is *weaker* than a Conservative Exclusive Ownership (S-CEO) break, which
requires the identical signature to verify under a second key. It is precisely a failure of
**non-separability** for combined signature schemes.

## Technical detail

What each component signs today:

| Scheme / mode | Ed25519 input | ML-DSA context | SLH-DSA context |
|---|---|---|---|
| `hybridedmldsaslhdsa` full (id 4) | `m`, pure Ed25519 | `{4}` | `{4}` |
| `hybridedmldsaslhdsa` compact (id 3) | `m`, pure Ed25519 | `{3} ‖ pk₃` | *(no component)* |
| `hybridedmldsaslhdsa5` full (id 5) | `m`, pure Ed25519 | `{5}` | `{5}` |
| `hybrideds` full (id 2) | `m`, pure Ed25519 | none (`SignNoContext`) | none (`NoContext`) |
| `hybrideds` compact (id 1) | `SHA3-512(nonce ‖ m ‖ pk₃)` | none (`SignNoContext`) | *(no component)* |

"Pure Ed25519" means RFC 8032 §5.1 `Ed25519`, which has **no** context or domain-separation
field at all (unlike `Ed25519ctx`). Two consequences follow.

**The scheme-ID byte is not a binding.** It distinguishes the *modes* from one another, but
it is a public constant that every signer uses, so an adversary uses it too. It records *how*
a signature was produced, never *under which composite key*.

**The Ed25519 component is the transplantable one.** In four of the five rows above it signs
the bare message. Therefore:

- it can be moved between composite keys — the basis of this finding;
- it is byte-identical across full and compact mode, so a single **compact** signature (the
  cheaper, default mode) yields a component that can be lifted into a forged **full**
  signature; the victim need never have produced a full signature
  (`TestEd25519ComponentIsCrossModeTransplantable`);
- it is a valid standalone RFC 8032 Ed25519 signature over `m`, and would be accepted by any
  external verifier that checks pure Ed25519 under `pk₁`.

### The instructive exception: `hybrideds` compact

`hybrideds` compact mode is **partially resistant**, and it demonstrates the fix empirically.
Both of its components sign `SHA3-512(nonce ‖ m ‖ pk₃)`. Because `pk₃` is inside that hash,
`μ₁` and `μ₂` do depend on `pk₃`, so the conjunction no longer factorises with respect to the
third component: substituting `pk₃` is **rejected**. `TestKeySubstitutionCompactMode` asserts
this as a control.

`pk₂` is committed to nowhere, so the ML-DSA half remains substitutable. Partial binding
yields exactly partial protection — which is the argument for binding all of `pk`.

## Reproduction

```
go test -run TestKeySubstitution ./sign/hybridedmldsaslhdsa/ ./sign/hybridedmldsaslhdsa5/ ./sign/hybrideds/
```

`TestKeySubstitutionFullMode` implements the four steps above. Note that the adversary's
key-generation and signing steps require no cryptographic capability whatsoever — the
adversary simply runs honest key generation and honest signing under keys it owns.
`UnmarshalPublicKey` likewise has nothing to reject: a composite public key carries no
internal binding between its parts, so any concatenation of correctly sized, individually
well-formed components is a well-formed composite key.

### Test convention

These are **characterization tests**: they assert the behaviour the code has *today*, so CI
stays green and the finding remains executable rather than prose-only.

They are also **tripwires**. Implementing the fix will make them fail — that is the intended
signal, not a regression. Each carries a `wantForgeryAccepted` constant to invert at that
point, together with instructions to rename the test to assert the secure property.

## Applicability

**No exploitable path exists in `quantum-coin-go`, `quantum-coin-js-sdk`, or `quantumcoin.js`.
No funds, accounts, node identities, consensus messages, or stored signatures in those
systems are at risk, and no operational or emergency action is required.**

The reason is uniform: every consumer derives identity from a hash of the **entire** composite
public key. Since `pk' ≠ pk` and the hash is collision-resistant, the derived identity
differs. The adversary's `pk'` is a genuine, well-formed key — it simply belongs to the
adversary, and (per bound 1 above) cannot sign anything the victim has not already signed.

### quantum-coin-go

| Trust decision | Mechanism | Binds full `pk`? |
|---|---|---|
| Account address | `crypto.PublicKeyBytesToAddress` = truncated `Keccak256(pk)` | yes |
| Transaction sender | `PublicKeyBytesFromSignature` reads `pk` carried in the signature envelope, verifies against it, then hashes that same `pk` | yes |
| Node identity | `V4ID.NodeAddr` = `Keccak256(serialized pk)` | yes |
| Validator / cross-sign identity | `PublicKeyToAddressNoError`, same whole-key hash | yes |

There is no ECDSA-style public key recovery anywhere in the codebase: the public key is
transported explicitly and hashed in full. An adversary therefore cannot present a signature
that resolves to the victim's address.

### quantum-coin-js-sdk

`newWallet`, `openWalletFromSeed`, and `deserializeEncryptedWallet` all derive the wallet
address through `PublicKeyToAddress` over the complete composite key. `verifyWallet`
additionally performs a sign/verify round-trip against the wallet's own key pair.

### quantumcoin.js

`verifyMessage` calls `qcsdk.publicKeyFromSignature` and then `computeAddress(pubHex)`. A
substituted key resolves to the **adversary's** address, never the victim's. The function
answers "which address signed this", and the answer it returns is correct.

### The invariant this relies on

> Every consumer decision meaning *"this identity authorised this message"* must be keyed on
> a hash of the **complete** composite public key — never on a component, a prefix, or any
> proper subset.

The invariant holds throughout all three consumers today. It is, however, enforced only by
convention: it is not stated in the schemes' documentation and nothing in `sign/` checks or
requires it. It would be broken by, for example:

- an identity, address format, or index key derived from a *prefix* or single component of
  the composite key (`pk₁` is the natural candidate, being smallest and most familiar);
- an off-chain attestation, login challenge, or proof-of-control flow that concludes the
  victim signed because their Ed25519 component verifies;
- a bridge, light client, or external verifier that checks fewer than all components;
- reuse of any component key outside the hybrid — recall `σ₁` is a valid pure Ed25519
  signature over `m`.

A signature scheme should not depend on an unstated property of its callers. That, rather
than any present exposure, is the substance of this finding.

## Recommended fix

Apply the BUFF transform: bind the composite public key into every component's signed input.
Compute once per operation

```
bind = SHA3-256( domainString ‖ schemeID ‖ pk₁ ‖ pk₂ ‖ pk₃ )
```

with `domainString` a fixed, scheme-unique ASCII label, and include `bind` in every `μᵢ`:

- **ML-DSA, SLH-DSA** — append `bind` to the existing context. Both already accept one, and
  both remain FIPS 204 / FIPS 205 conformant, since the context is a caller-chosen field.
- **Ed25519** — either switch to `Ed25519ctx` (RFC 8032 §5.2) with `bind` as the context, or
  sign `H(bind ‖ m)` in place of the bare message. The latter avoids a second Ed25519 code
  path and keeps the component a plain `Ed25519` call.

Sequencing notes:

- This is a **wire-format change**. Signatures produced under the new rule will not verify
  under the old and vice versa, so it requires a new scheme identifier and a consensus
  activation height, not a silent in-place edit.
- These packages currently have **no known-answer vectors** pinning the signature
  construction — every signing test is a self-round-trip. KAT vectors should land *before or
  with* the fix, or the migration has no fixed reference to verify against.
- `hybrideds` is legacy and frozen for backward compatibility. The realistic plan is to fix
  the ML-DSA/SLH-DSA schemes under new identifiers and leave `hybrideds` documented as-is.
- Because impact on current consumers is nil, this is a **planned hardening item, not an
  incident**. It should be scheduled alongside the next scheme-ID revision rather than
  rushed.

## References

**Tests in this repository**

- `sign/hybridedmldsaslhdsa/keysubstitution_test.go` — full mode, compact mode, cross-mode
  component transplantability
- `sign/hybridedmldsaslhdsa5/keysubstitution_test.go` — full mode
- `sign/hybrideds/keysubstitution_test.go` — full mode, compact mode, plus the `pk₃`
  substitution control that demonstrates partial binding working

**Literature**

- S. Blake-Wilson, A. Menezes, *Unknown Key-Share Attacks on the Station-to-Station (STS)
  Protocol*, PKC 1999 — origin of duplicate-signature key selection (DSKS).
- A. Menezes, N. Smart, *Security of Signature Schemes in a Multi-User Setting*, Designs,
  Codes and Cryptography 33(3), 2004.
- T. Pornin, J. Stern, *Digital Signatures Do Not Guarantee Exclusive Ownership*, ACNS 2005.
- N. Bindel, U. Herath, M. McKague, D. Stebila, *Transitioning to a Quantum-Resistant Public
  Key Infrastructure*, PQCrypto 2017 — formalises non-separability for **combined** signature
  schemes; the notion this finding concerns.
- C. Cremers, S. Düzlü, R. Fiedler, M. Fischlin, C. Janson, *BUFF: Beyond UnForgeability
  Features with Application to Post-Quantum Signatures*, IEEE S&P 2021 — exclusive ownership,
  message-bound signatures, non-resignability, and the generic `H(pk ‖ m)` transform
  recommended above.

[CWE-345]: https://cwe.mitre.org/data/definitions/345.html
[CWE-347]: https://cwe.mitre.org/data/definitions/347.html
