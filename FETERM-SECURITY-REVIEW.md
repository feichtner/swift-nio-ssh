# Security review — feterm-patches, 2026-08-24

A code-level review of this fork's delta over `apple/swift-nio-ssh`,
plus the fork's repo posture. Every claim below was checked against
code, wire behaviour, or the GitHub API — not restated from intent.
Fixes found during the review landed in the same change as this file.

## Scope and baseline

Four patches ahead of upstream `main`, zero behind (verified at review
time): the external-signer hook, the sntrup761 hybrid KEX with its C
target, the negotiated-algorithms accessor, and the ML-KEM hybrid KEX.
361 tests green on macOS and Linux (swift:6.2).

## Patch 1 — `NIOSSHCustomPrivateKey` (external signer)

The auth-critical one. Its safety rests on a single invariant, verified
by reading the parse path: **hostile wire data can never produce a
`.custom` key.** `readPublicKeyWithoutPrefixForIdentifier` dispatches
only to ed25519/ECDSA/certified readers, so the patch's always-false
signature verification and the `preconditionFailure` in the certificate
path are unreachable from network input — `.custom` exists only when
the client app constructs it. Custom keys cannot sign KEX digests
(throws) and cannot act as host keys. Signing may block on user
interaction; the requirement to give such connections a private event
loop is documented on the protocol. **Sound.**

## Patches 2 & 4 — the hybrid post-quantum key exchanges

- **Vendored primitive**: `sntrup761.c` verified byte-identical to
  openssh-portable at review time (and the new fork CI re-checks this
  on every push). Public domain, provenance in the target README.
- **Shims**: `randombytes` aborts on entropy failure (arc4random_buf on
  Darwin, chunked getentropy on Linux — proceeding without randomness
  would be worse than crashing); the optblocker volatiles match
  upstream's definitions; `explicit_bzero` maps to `memset_s` on
  Darwin. The shim SHA-512 is pinned to FIPS 180-4 known-answer vectors
  and cross-checked against swift-crypto across all padding paths; its
  <2^61-byte input contract is now documented in the header (inputs top
  out ~1.2 KB in practice).
- **Wire handling**: both public values are hard-length-checked before
  splitting; K is hashed as an SSH `string` (not mpint) per both
  drafts, in the exchange hash *and* the key derivation; the X25519
  half rejects the all-zero shared secret on both roles; ML-KEM public
  keys are validated by swift-crypto's parser. Implicit rejection
  (tampered ciphertext → different key, never an error) surfaces as an
  exchange-hash signature failure, which tests pin.
- **Secret hygiene**: the client's KEM secret is single-use (consumed
  and nil'ed before decapsulation; a second reply throws), and raw
  secret buffers are zeroized after use — best-effort under Swift CoW
  semantics, stated as such in the code.
- **Interop, not self-agreement**: both exchanges were verified against
  real OpenSSH servers pinned to accept ONLY the respective algorithm
  (9.6 for sntrup761, 10.0 for ML-KEM), and the consuming app's CI
  keeps those pins across an 8.9/9.6/10.0 matrix.
- **Negotiation downgrade**: stripping the hybrid names from a KEXINIT
  in transit is detected the standard way — both KEXINIT payloads are
  in the exchange hash the server signs.

## Patch 3 — negotiated-algorithms exposure

Read-only metadata (algorithm names), event-loop-confined like the rest
of the handler API, captured at negotiation time. No secret material,
no new parse surface. **Sound.**

## Inherited-from-upstream observations (not this fork's delta)

- **Terrapin (CVE-2023-48795)**: NIOSSH implements neither strict KEX
  nor the vulnerable modes. The only ciphers are AES-GCM, which the
  attack cannot exploit (its nonce is independent of the sequence
  number), so the missing countermeasure is a **hardening gap, not a
  vulnerability** — it becomes load-bearing only if ChaCha20-Poly1305
  or CBC-EtM is ever added. Revisit then, or upstream strict-KEX first.
- `SSH_MSG_IGNORE`/`DEBUG` are tolerated during key exchange
  (RFC-legal; harmless with AES-GCM for the same reason).
- No `ext-info` support — nothing for an attacker to strip, but also no
  `server-sig-algs` (already noted in the consuming app).

## Repo posture (findings → fixed in this review)

| Finding | Severity | Status |
| --- | --- | --- |
| `feterm-patches` had no branch protection: history was force-pushable on a public repo consumed by a real app | Medium | **Fixed** — ruleset `feterm-patches-immutable-history` (no deletion, no force-push) on `feterm-patches` and `main`. Consumers were already revision-pinned via Package.resolved, so builds could not be silently retargeted; the ruleset closes tampering with future updates. |
| The fork's own 361-test suite ran only on the maintainer's machine — the consuming app's CI compiles these sources but never executes this package's tests | Medium | **Fixed** — `feterm-ci.yml` runs the suite in swift:6.2 on hosted runners for every push/PR to `feterm-patches`, and warns when the vendored `sntrup761.c` drifts from openssh-portable master. |
| SHA-512 shim silently wrong above 2^61 bytes | Low | **Fixed** — contract documented at the declaration; unreachable from sntrup761. |
| ML-KEM keygen `try!` aborts on entropy failure | Info | By design — identical to the C shim's `abort()`; documented at the call. |

## Modern language features audit (2026-08-24 addendum)

What the security-relevant Swift feature set looks like here, verified
against the actual compile flags rather than the manifest:

**In effect:**
- **Swift 6 language mode** on the NIOSSH target (checked in the build
  invocation: `-swift-version 6`) — compile-time data-race safety covers
  all four patches; `Sendable` is enforced, not advisory.
- **MemberImportVisibility** upcoming feature (upstream's cross-repo
  settings block) — no API reachable through transitive imports.
- All Swift-side cryptography via swift-crypto; the only non-library
  primitive is the vendored, drift-checked sntrup761.

**Evaluated, not adopted — with reasons:**
- **Noncopyable single-use secrets** (`~Copyable`, SE-0390/0427): the
  natural fit for the KEM secret's single-use invariant, but a
  noncopyable stored field makes the containing key-exchange struct
  noncopyable, and upstream's connection state machine copies exchanger
  values between states — adopting it means forking the state machine,
  which loses diffability for a guarantee the code already enforces
  dynamically (secret consumed and nil'ed; second use throws; pinned by
  tests). Worth revisiting if upstream ever adopts noncopyable state.
- **CoW audit in lieu of it**: verified that the current `[UInt8]`
  secret has exactly one buffer end to end — state-machine copies share
  it (no intervening writes), and zeroization happens on the sole owner
  after decapsulation. The dynamic guarantee is real, not aspirational.
- **Strict memory safety** (`-strict-memory-safety`, SE-0458): would
  flag every `withUnsafeBytes` in upstream code — hundreds of warnings
  on a fork meant to stay diffable. Right tool for upstream, not for a
  patch branch.
- **Span/InlineArray** (SE-0447/0453): the C boundary passes exact-size
  whole buffers with no slice arithmetic, which is the failure mode
  those types remove; adopting them here would churn interop code
  without closing a reachable bug class.

## Standing recommendations

1. Track upstream: re-run `git rev-list --count` both ways before each
   consuming-app release; upstream security fixes should be rebased
   under the four patches promptly.
2. If a fifth patch ever adds ChaCha20-Poly1305, implement strict KEX
   (`kex-strict-c-v00@openssh.com`) in the same change — see the
   Terrapin note above.
3. Upstreaming the KEX patches to `apple/swift-nio-ssh` would retire
   most of this document; they are deliberately self-contained for it.
