# FINDING-002: Signing mode is not bound into every component's signed input

**Status:** Open (documented, not fixed)
**Affects:** `sign/hybrideds` (primary), `sign/hybridedmldsaslhdsa` (partial);
`sign/hybridedmldsaslhdsa5` is structurally out of scope (single mode)
**Class:** Cross-protocol / mode-confusion attack — failure of domain separation between
two signing modes that share one key pair
**CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html) (Insufficient Verification
of Data Authenticity) — the signed payload is not bound to the mode that produced it.
**Severity:** Medium — latent. Rated per the scale in [SECURITY_AUDIT.md](../SECURITY_AUDIT.md#methodology):
violates a hardening notion beyond unforgeability, and becomes an existential forgery under a
plausible parameter change. In `sign/hybrideds` the property that prevents exploitation is an
*incidental payload-length asymmetry*, not domain separation; two independent,
individually-innocuous parameter changes make it an existential forgery.
**Reachability:** Not reachable — every message reaching the library is a 32-byte digest, the
length is enforced in both modes regardless of caller, and no consumer invokes `hybrideds`
full-mode signing on any path (see [Applicability](#applicability)).
**Reproduction:** `crossmodeseparation_test.go` in each affected package.

Related: [FINDING-001](FINDING-001-key-substitution.md) concerns binding the *composite
public key* into component inputs. This finding concerns binding the *mode*. They share a
root cause — too little bound into what each component signs — and overlap at exactly one
observation (the Ed25519 component of `hybridedmldsaslhdsa` is mode-agnostic). They are
otherwise distinct: FINDING-001 varies the key and holds the message fixed; FINDING-002
varies the message and holds the key fixed.

---

## Summary

`hybrideds` and `hybridedmldsaslhdsa` each expose two signing modes — *compact* and *full*
— over a **single key pair**. Each mode applies its own transformation to the caller's
message and hands the result to the component signature schemes.

A multi-mode scheme is cross-mode separated only if no signature issued in one mode can be
reinterpreted as a component signature in the other. The standard way to guarantee this is
domain separation: prefix a mode-unique domain separator inside every component's signed
input.

`hybrideds` does not do this for any component. Its two modes are distinguished only by the
*length* of the byte string that gets signed — 32 bytes in full mode, 64 in compact. That
happens to be sufficient today. It is not a cryptographic property of the construction, and
it is not stated anywhere as an invariant.

## Formal statement

Fix a key pair `(pk, sk)`. For mode `m ∈ {compact, full}` let

```
P_m : M → {0,1}*
```

be the *payload map*: the function carrying the caller's message to the exact byte string
handed to each component signer. Signing in mode `m` computes component signatures over
`P_m(msg)`; verification in mode `m` recomputes `P_m(msg')` and checks the components
against it.

Cross-mode separation is the requirement

```
Image(P_compact) ∩ Image(P_full) = ∅                                    (†)
```

If (†) fails and the intersection is *reachable* — i.e. an adversary can name a message
`m₁` with `P_full(m₁) = P_compact(m₂)` for a target `m₂` of their choosing — then a single
query to a mode-`full` signing oracle yields component signatures that the mode-`compact`
verifier accepts on `m₂`. Since `m₂` was never submitted to the oracle, this is an
existential forgery under chosen-message attack: the multi-mode scheme is not EUF-CMA
secure, even though each component scheme in isolation is.

Note (†) is a property of the *construction*. Domain separation discharges it
unconditionally; a length argument discharges it only for as long as the lengths stay
distinct.

## Technical detail

### What each component actually signs

| Scheme / mode | Ed25519 signed input | ML-DSA context | SLH-DSA context |
|---|---|---|---|
| `hybrideds` full (id 2) | `msg`, \|msg\|=32, RFC 8032 pure (no `dom2`) | none — `SignNoContext` | none — `SignRandomizedNoContext` |
| `hybrideds` compact (id 1) | `SHA3-512(nonce ‖ msg ‖ pk_slhdsa)`, 64 bytes | none — `SignNoContext` | *(component absent)* |
| `hybridedmldsaslhdsa` full (id 4) | `msg`, \|msg\|=32, pure | `{4}` | `{4}` |
| `hybridedmldsaslhdsa` compact (id 3) | `msg`, \|msg\|=32, pure | `{3} ‖ pk_slhdsa` | *(component absent)* |
| `hybridedmldsaslhdsa5` full (id 5) | `msg`, \|msg\|=32, pure | `{5}` | `{5}` |

`SignNoContext` / `VerifyNoContext` are ML-DSA `Sign_internal` / `Verify_internal`
(`sign/mldsa/mldsa44/dilithium.go`): they compute `μ = H(tr ‖ payload)` and deliberately
omit the FIPS 204 message encoding `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ msg`. This omission is
intentional and load-bearing for wire compatibility with the pre-2025-07-29 cgo
implementation; it is noted here only because it means **no** domain separator reaches
ML-DSA in `hybrideds`.

### `sign/hybrideds` — separation rests on a length coincidence

```
P_full(msg)    = msg                                   with |msg| = 32 enforced
P_compact(msg) = SHA3-512(nonce ‖ msg ‖ pk_slhdsa)      always 64 bytes
```

(†) holds: every element of `Image(P_full)` is a 32-byte string and every element of
`Image(P_compact)` is a 64-byte string, so the images are disjoint as sets. Both consuming
primitives — RFC 8032 pure Ed25519 and ML-DSA `Sign_internal` — absorb the payload as a raw
byte string with no length-independent encoding, so byte strings of different lengths are
distinct signed inputs, and disjointness is exact rather than probabilistic.

The enforcement `len(msg) != CRYPTO_MSG_LENGTH → error` lives inside both `Sign` and
`SignCompact` (`hybrideds.go`), so it holds regardless of caller behaviour. That is a
genuine and valuable property: the scheme is fail-closed against a careless caller.

What it is not is domain separation. (†) is discharged by an arithmetic accident —
`32 ≠ 64` — between two constants chosen for unrelated reasons. Either of the following
changes, each locally reasonable, collapses the images together and makes the forgery live:

- **(a)** `CRYPTO_MSG_LENGTH := 64` (e.g. to admit SHA-512 digests). `Image(P_full)` then
  contains 64-byte strings; an adversary queries full mode on `H = P_compact(m*)` and lifts
  the Ed25519 and ML-DSA components into a compact signature over `m*`.
- **(b)** the compact digest shortened to 32 bytes (SHA3-256, or truncation, e.g. to reduce
  signature size). Symmetric collapse, same consequence.

`TestShrinkingCompactDigestWouldReintroduceForgery` instantiates (b) against the real key
material and confirms both lifted components verify under the hypothetical 32-byte-digest
compact verifier. The failure mode is therefore demonstrated, not merely argued.

Independent corroboration: the C reference implementation of this same construction
(`hybrid-pqc`, `hybrid-dilithium-sphincs/hybrid.c`) instantiates precisely the collapsed
parameters — its `MAX_MSG_LEN` is a *variable* 1..64 and its `HASH_LENGTH` is 64, so
`Image(P_full) ⊇ Image(P_compact)` — and is existentially forgeable. That implementation is
out of scope for this document; it is cited only as evidence that (a)/(b) describe a
reachable failure, not a theoretical one.

### Why the per-signature nonce is not a mitigation

The compact payload includes a fresh random 40-byte nonce, which reads at first glance like a
defence against exactly this attack. It is not, and the reason is worth stating explicitly
because it is the first objection a reviewer raises.

`VerifyCompact` reads the nonce **out of the signature** and recomputes the hash from it; it
never re-derives or constrains it. The nonce is therefore a plain public field, and in a
*forgery* the adversary supplies it. The attack order is:

1. The adversary picks the target message `m₂` **and** a nonce `N` of their choosing.
2. They compute `H = SHA3-512(N ‖ m₂ ‖ pk_slhdsa)` entirely offline.
3. They obtain a **full-mode** signature on `H` from the victim.
4. They assemble a compact signature embedding `N`; `VerifyCompact` recomputes the same `H`.

The victim's own nonce never participates. What blocks step 3 today is the payload-length check
— `|H| = 64` and full mode enforces exactly 32 — which is the fragile invariant this finding is
about, not the nonce. If anything the nonce marginally *helps* the adversary: it yields ~2^320
admissible values of `H` for a fixed target rather than one, though only one is needed.

A nonce contributes cross-mode separation only when bound to something the adversary cannot
choose — a signer secret, or a verifier-supplied challenge. This one is neither. Its actual
function is to randomise the compact payload so that signing the same message twice yields
distinct signed values; that is payload non-determinism, a different property.

`crossmodeseparation_test.go` already encodes this: the attacker picks both the target message
and the nonce.

### `sign/hybridedmldsaslhdsa` — separation is cryptographic but single-layered

Here the ML-DSA context differs by mode (`{4}` vs `{3} ‖ pk_slhdsa`), and FIPS 204 binds
`ctx` into `M'`, so ML-DSA components are not interchangeable between modes. (†) is
discharged cryptographically and does not depend on any length invariant.

However `P_compact = P_full = identity` for the **Ed25519** component: both modes sign the
bare 32-byte message with an empty RFC 8032 context. The Ed25519 component of a compact
signature is therefore, bit for bit, a valid Ed25519 component of a full signature over the
same message, and vice versa. `TestEd25519ComponentIsModeAgnostic` asserts this.

This is not by itself a forgery: completing a full signature additionally requires ML-DSA
under context `{4}` and SLH-DSA under `{4}`, both under the victim's key, which the
adversary does not have. The accurate characterisation is that **all** cross-mode
separation in this scheme is carried by the ML-DSA (and, for full mode, SLH-DSA) context,
and none by Ed25519.

The security consequence should not be overstated. In compact mode ML-DSA is also the sole
source of post-quantum unforgeability, so an adversary who can defeat ML-DSA has already
broken compact mode outright; the absent Ed25519 mode-binding does not make that worse. The
substantive objection is structural: a hybrid construction should not concentrate a
security property in one component when binding it in all three is free. The composition of
this observation with FINDING-001 — where the attacker supplies their *own* ML-DSA and
SLH-DSA keys — is what turns Ed25519 mode-agnosticism into a usable primitive, and is
tracked there.

### `sign/hybridedmldsaslhdsa5` — out of scope

The package exposes only `Sign`/`Verify` (scheme id 5); there is no compact mode, hence no
pair of modes over one key pair and no instance of (†) inside the package. The scheme ID is
nonetheless bound into both the ML-DSA and SLH-DSA contexts, so the construction is
consistent with the recommended fix. `TestNoCompactModeExists` records this so that adding
a second mode later trips a test rather than silently inheriting this finding.

### Cross-*scheme* transplantation

Because `hybrideds` full, `hybridedmldsaslhdsa` full/compact and `hybridedmldsaslhdsa5`
full all sign the bare 32-byte message with pure Ed25519, an Ed25519 component is
syntactically valid across all four. This is inert while an Ed25519 key is confined to one
composite key, which the package documentation already requires
(`hybridedmldsaslhdsa.go`: component keys "MUST NOT be reused in any other signing
context"). It is recorded here because it is the same missing binding viewed across
schemes rather than across modes, and because it is what makes FINDING-001's substitution
step cheap.

## Reproduction

```
go test -run "TestCrossMode|TestEd25519Component|TestNoCompactMode|TestShrinking" \
  ./sign/hybrideds/ ./sign/hybridedmldsaslhdsa/ ./sign/hybridedmldsaslhdsa5/
```

### Test convention

Following FINDING-001, these are **characterization tests**: they assert today's behaviour
so CI stays green and the finding stays executable rather than prose-only. They are also
**tripwires** — `TestShrinkingCompactDigestWouldReintroduceForgery` and
`TestEd25519ComponentIsModeAgnostic` will fail once domain separation lands, which is the
intended signal to invert their assertions and rename them to the secure property.

## Applicability

**No exploitable path exists in any of the three consumers today.** Two independent reasons
hold across all of them: every message passed to circl is a 32-byte digest, and circl's own
`len(msg) != CRYPTO_MSG_LENGTH` check rejects anything else in both modes regardless of
caller behaviour.

Additionally — and decisively for the two SDKs — **no consumer invokes `hybrideds` full
mode for signing at all**. quantum-coin-go forbids scheme id 2 for transactions in every
block regime, and the JavaScript SDKs contain no call to `hybrideds` full-mode signing on
any path. The full-mode signing oracle that this finding's attack requires is therefore not
reachable through any supported consumer API, independently of message length.

The consumers are recorded separately below because the reasons differ, and because the
two JavaScript SDKs carry a deployment-context constraint that bounds their threat model.

### quantum-coin-go — not applicable, widest margin

Three independent barriers, any one of which is sufficient:

1. **Payload length.** All signing enters through `SigAlg.Sign(digestHash, prv)` with
   `digestHash` a 32-byte Keccak-256 output. The pre-circl cgo wrappers enforced
   `len(message) != CRYPTO_MESSAGE_LEN` (=32) themselves; today circl enforces it
   internally, so the check no longer depends on the caller.
2. **Scheme-ID gating.** `DynamicVerifier.IsSignatureTypeAllowedForTxn`
   (`crypto/cryptobase/cryptobase.go`) never admits `DILITHIUM_ED25519_SPHINCS_FULL_ID`
   (id 2) for a transaction in any block regime — not default, not sig-alg-switch, not
   breakglass. The full-mode signing oracle this finding requires is therefore not
   reachable for on-chain transactions at all.
3. **Wrapper-level domain separation.** `HybridedsfullSig.SignWithContext`
   (`crypto/hybridedsfull/hybridedssigfull.go`) signs `Keccak256(digestHash ‖ context)`
   with `context[0]` the scheme ID, which supplies at the wrapper layer the binding the
   library omits.

Note that barrier 2 is regime-dependent: in the pre-2025-07-29 cgo era the corresponding
predicate did admit id 2 under breakglass. Barrier 1 held throughout, in both the compact
and full wrappers, so no era was exposed.

### Deployment context for the two JavaScript consumers

`quantum-coin-js-sdk` and `quantumcoin.js` are **QuantumCoin-specific SDKs, not
general-purpose cryptographic libraries**. They are supported only for building QuantumCoin
wallets, dApps and tooling. Their threat model is therefore bounded by that context: the
relevant callers are QuantumCoin applications signing QuantumCoin payloads, and every such
payload is a 32-byte digest (see below). Usage outside that context — treating the embedded
circl WASM as a general signing library — is unsupported, and the analysis below does not
extend to it.

### quantum-coin-js-sdk — not applicable

The SDK never invokes `hybrideds` full mode. Across the whole SDK the only `hybrideds`
entry points called are `signCompact` (transaction signing), `verifyCompact`, and `verify`;
there is **no call to `hybridedsNs.sign`** anywhere. Signature *verification* accepts
scheme id 2, but that is inert here — the attack requires a full-mode signing **oracle**,
not a full-mode verifier.

The SDK's generic `sign(privateKey, message, signingContext)` routes exclusively to the
ML-DSA schemes:

| `signingContext` | scheme invoked | scheme id |
|---|---|---|
| `null` (key-type derived) | `hybridedmldsaslhdsa.signCompact` or `hybridedmldsaslhdsa5.sign` | 3 or 5 |
| `0` | `hybridedmldsaslhdsa.signCompact` | 3 |
| `1` | `hybridedmldsaslhdsa5.sign` | 5 |
| `2` | `hybridedmldsaslhdsa.sign` | 4 |

The only "full" mode reachable through the SDK API is therefore scheme id 4
(`hybridedmldsaslhdsa`), whose cross-mode separation is cryptographic (ML-DSA context), not
length-based. The `hybrideds` pair that this finding concerns is reachable for *signing*
only in compact mode.

Two residual notes, neither exploitable in the supported context:

1. circl's WASM layer does export `circl.hybrideds.sign` (full, id 2) on the global
   namespace, taking a caller-supplied `Uint8Array` with **no length validation at the
   binding layer** — `msg` passes straight to `hybrideds.Sign`. Reaching it requires an
   application to bypass the SDK's public API and call the raw namespace directly, which is
   outside the supported QuantumCoin usage described above. Even then, circl's internal
   `len(msg) != 32` check refuses the 64-byte payload the attack needs.
2. Because the binding surface is broader than the SDK's own API, the length invariant is
   the last line of defence for anything that does reach the raw namespace. That is an
   argument for treating `CRYPTO_MSG_LENGTH` and the compact digest length as security
   parameters of the library rather than implementation details — not an argument that this
   consumer is currently exposed.

### quantumcoin.js — not applicable

Depends on `quantum-coin-js-sdk` (`package.json`) and performs no signing of its own: it
contains no reference to `circl.*`, the hybrid namespaces, or the WASM bundle, and routes
all cryptographic operations through `qcsdk.*`. Its exposure is exactly that of the SDK.

Its arbitrary-message API (`Wallet.signMessage` / `signMessageSync`, which implements the
ethers `Signer` contract) is the one place a QuantumCoin dApp signs application-chosen
bytes rather than a transaction. It is not a path to this finding: the message is reduced
to a 32-byte digest before signing, and the signature is produced through the SDK's `sign`,
which — per the table above — never selects `hybrideds` full mode.

### The invariant this depends on

> For `sign/hybrideds`, `Image(P_compact)` and `Image(P_full)` must remain disjoint. Today
> that holds because `CRYPTO_MSG_LENGTH = 32` and the compact digest is SHA3-512 (64
> bytes). Any change that makes the compact digest 32 bytes, or admits 64-byte messages,
> reintroduces an existential forgery.

Nothing in `sign/` states or checks this, and neither constant is annotated as
security-relevant. `TestShrinkingCompactDigestWouldReintroduceForgery` is the executable
statement of the invariant.

## Recommended fix

Bind the mode into every component's signed input, so that (†) holds by construction rather
than by parameter choice. Compute once per operation

```
bind = SHA3-256("<scheme-domain-string>" ‖ schemeID ‖ …)
```

and include it in the signed input of **all** components:

- **ML-DSA / SLH-DSA:** append to the existing context. `hybridedmldsaslhdsa`(5) already do
  this with the scheme ID; `hybrideds` passes no context at all and would have to move off
  `SignNoContext`.
- **Ed25519:** switch to `ed25519.SignWithCtx` / Ed25519ctx (RFC 8032 §5.1 `dom2`), or sign
  `H(bind ‖ msg)` rather than the bare message. This is the component that currently
  contributes no mode binding in any scheme.

This is the same remediation FINDING-001 recommends; a single construction change
(`bind` covering scheme ID **and** the full composite public key) discharges both findings.
Fixing them together avoids two consecutive wire-format breaks.

Sequencing notes:

- This is a **wire-format break**: existing signatures will not verify under the new rule
  and vice versa. It requires a new scheme ID and a consensus-activation height, not a
  silent in-place change.
- There are currently **no known-answer vectors** pinning the signature construction in any
  of these packages — every signing test is a self-round-trip. KATs should land *before or
  with* the fix, or the migration has nothing to verify against.
- `hybrideds` is legacy and frozen for wire compatibility with the pre-2025-07-29 cgo
  implementation. The realistic plan is to fix the ML-DSA/SLH-DSA schemes under new IDs and
  leave `hybrideds` documented rather than changed — in which case the length invariant
  above becomes a permanent, and permanently unstated, security dependency. At minimum it
  should be promoted to a comment on `CRYPTO_MSG_LENGTH` and on the compact digest
  construction.

## References

- Test: `sign/hybrideds/crossmodeseparation_test.go` (length-based separation + the
  counterfactual collapse)
- Test: `sign/hybridedmldsaslhdsa/crossmodeseparation_test.go` (ML-DSA context is the sole
  separator; Ed25519 is mode-agnostic)
- Test: `sign/hybridedmldsaslhdsa5/crossmodeseparation_test.go` (no second mode exists)
- [FINDING-001](FINDING-001-key-substitution.md) — composite public key not bound into
  component signatures; shares the remediation
- FIPS 204 §5.2 — ML-DSA `M'` encoding, the mechanism by which `ctx` is bound
- RFC 8032 §5.1 — Ed25519 `dom2` prefix, absent in the pure variant used here
- Menezes & Smart, *Security of Signature Schemes in a Multi-User Setting*
- IETF LAMPS composite ML-DSA drafts — prior art for binding scheme identity and composite
  key into every component's signed input
