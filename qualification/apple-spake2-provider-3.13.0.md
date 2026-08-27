# Apple restricted SPAKE2+ provider qualification

## Baseline and scope

- Starting AuroraACP HEAD: `79b9551fae0e34e7484f78af1c05e386b881ede7`.
- Final reviewed HEAD is recorded in the delivery report after the reviewed commits.
- Only AuroraACP was writable. No other Aurora-family repository was modified.
- Botan was not patched, forked, or modified.
- X.509 issuer and signing-key custody design were not implemented.

## Pinned provider and build

- Botan: official source release `3.13.0`.
- SHA-256: `12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620`.
- Targets: macOS 13 arm64, iOS 16 arm64, iOS 16 arm64 Simulator.
- Frozen module closure: `argon2`, `asn1`, `base`, `base64`, `bigint`,
  `blake2`, `codec`, `ec_group`, `enc_padding`, `hash`, `hex`, `hkdf`,
  `hmac`, `kdf`, `mac`, `math`, `mdx_hash`, `mp`, `numbertheory`, `pbkdf`,
  `pcurves`, `pcurves_impl`, `pcurves_secp256r1`, `pem`, `pubkey`, `rng`,
  `sha2_32`, `sha2_64`, `spake2p`, `system_rng`, `utils`.
- `pcurves_secp256r1` is asserted after every configure operation; exact
  module equality is a build gate, not an informational check.

Botan's SPAKE2+ module pulls password-registration dependencies such as Argon2
into the static implementation closure. The ACP API does not expose password
hashing, Argon2 parameters, arbitrary algorithms, or any generic Botan entry
point.

## Restricted API and lifecycle

The packaged header exposes eight functions: registration record creation,
fixed prover/verifier creation, prover share generation, verifier share
processing, atomic prover response/confirmation/key consumption, atomic
verifier confirmation/key consumption, and deterministic destruction.

There is no shared-secret getter and no `skip_confirmation` operation.
Confirmation processing and moving the 32-byte key out of provider custody are
one atomic terminal transition. Success consumes the provider context; every
error terminalizes it. The Swift result has a package-owned initializer and
package-owned accessor, so product code cannot fabricate or extract it.

Every native input and output includes an explicit length. The wrapper enforces
32-byte canonical nonzero scalars, the exact 64-byte `w0 || w1` form, 65-byte
shares, 97-byte registration records/responses, 32-byte confirmations/keys,
255-byte identity limits, and a 4096-byte context limit. Null, zero-capacity,
wrong-size, overlapping, malformed-point, malformed-record, and invalid-state
inputs fail closed.

## Secrets and errors

Botan secure containers own scalar and shared-secret material internally. The
wrapper stages the final key in a fixed buffer, explicitly wipes it on every
exit, destroys the Botan context immediately after terminal confirmation, and
wipes failed outputs. Swift immediately moves the key into `ACPSecretBytes`
and resets its transient `Data` buffer. `ACPSecretBytes` redacts descriptions
and clears storage on explicit clear/deinitialization.

The compiler and Swift runtime cannot provide a proof that every optimized or
copy-on-write physical copy is erased. The implementation therefore minimizes
copies and uses volatile native wiping plus `Data.resetBytes`, which are the
strongest available primitives at these boundaries.

Native failures are normalized to bounded ACP categories. Swift exposes only
authentication failure or resource/provider failure and never forwards Botan
exception text, scalar details, transcript intermediates, or confirmation
comparison details.

## Visibility, S9, and symbols

The XCFramework contains only the ACP header and static library. It contains no
Botan header, Botan module map, generic Botan C FFI symbol, or importable ACP C
module. `AuroraACPAppleSecurity` uses private link-only declarations. A clean
external consumer depending on the public Swift product fails with `no such
module 'AuroraACPSPAKE2'` when it attempts a direct import.

Public Swift symbol graphs contain no Botan type, C handle, `OpaquePointer`, or
`acp_spake2_*` entry point. The S9 fabrication audit passes: the opaque PAKE
result cannot construct a principal, authenticated connection, TLS evidence,
enrollment success, trusted-peer state, credential state, or transport proof.

Static archives necessarily retain upstream Botan C++ symbols. They are link
implementation details without packaged headers/module maps. Wrapper-internal
C++ symbols are Mach-O `private external`; the only ordinary external wrapper
symbols are the eight reviewed `acp_spake2_*` functions. This report does not
claim that static archive members are physically absent.

## Vectors and negative qualification

- RFC 9383 Appendix C P-256/SHA-256: byte-for-byte shareP, shareV/confirmV,
  confirmP, and K_shared PASS through a test-only deterministic wrapper build.
- ACP RAW128 provider-independent frozen vectors: PASS and unchanged.
- Production wrapper prover/verifier randomized agreement: PASS on macOS and
  iOS Simulator.
- Invalid scalar/record/point, wrong confirmation, wrong sizes, premature
  confirmation, duplicate operations, terminal failure reuse, identity/context
  bounds, and one-shot result cases: PASS.
- Deterministic RNG control exists only under `ACP_SPAKE2_TESTING`; it is absent
  from the packaged header and production artifacts.

## Packaging and reproducibility

Headers are copied as ordinary files. Botan's generated symlink tree is never
passed to `xcodebuild -create-xcframework`. Packaged symlinks are a hard error.
The builder normalizes plist key and library ordering, file modes, mtimes,
static-archive member timestamps/owners/groups/modes, and build path strings.

Independent clean Builds I and J each re-extracted and re-hashed the official
archive, configured and compiled every slice, checked the exact module closure,
compiled/linked the smoke program, staged real headers, and created the package.

- Canonical manifest I SHA-256: `88c6d951c7f6d892a6e60086d39e1ab48f7d49f6838c1b0f4b885424cbeb8646`.
- Canonical manifest J SHA-256: `88c6d951c7f6d892a6e60086d39e1ab48f7d49f6838c1b0f4b885424cbeb8646`.
- Manifests: byte-identical.
- Every packaged file: byte-identical.
- macOS library: `97cdf458527757beced4d0ecfc232bfcc088dc2e434b48ea29d47c4a3f269306`.
- iOS library: `b26081f5adc0d72673bec9943062863609c3915efee22dce72e9fe7a0c70875f`.
- Simulator library: `7a2b2b2768b747dbea28443cb12f1ba07eb087665fa94e13d6088e7075c38adb`.

## Apple and regression results

- macOS 13 arm64 Swift compile/link and provider runtime: PASS.
- iOS 16 arm64 Swift compile/link: PASS; physical-device runtime NOT RUN.
- iOS 16 arm64 Simulator Swift compile/link and provider runtime: PASS.
- Swift: 128 tests PASS.
- Python: 244 tests PASS; Ruff PASS; mypy source audit PASS.
- Rust: 64 tests PASS; doc tests PASS; Clippy PASS; rustfmt PASS.
- Registry, 17 frozen security vector sets/31 hashes, fuzz smoke, S9 API audit,
  provider boundary audit, symbol graph audit, and `git diff --check`: PASS.

The existing iOS certificate policy uses macOS-only certificate extension APIs.
It is now explicitly fail-closed with `providerUnavailable` on iOS so the Apple
target can compile without pretending the excluded iOS X.509 policy work is
complete.

## Internal security review

1. Downstream Swift cannot import Botan or the restricted native module.
2. No alternative ciphersuite can be selected.
3. No `skip_confirmation` operation is present.
4. No pre-confirmation key getter exists.
5. `w0`/`w1` are length- and canonicality-checked before context creation.
6. Provider errors are normalized and contain no cryptographic detail.
7. Failed contexts are terminal and destroyed by the Swift adapter.
8. Transient application-visible buffers are minimized and wiped; physical
   zeroization limits are documented above.
9. The provider cannot fabricate higher-level ACP evidence.
10. Package-owned opaque results preserve S9 admission boundaries.
11. Missing `pcurves_secp256r1` fails the exact module gate and smoke test.
12. No unrestricted header or module is packaged.
13. Build-script drift changes the exact closure and fails the build.
14. A replaced source archive fails before extraction.
15. Builds I and J have identical manifests and per-file hashes.

No P0, P1, or P2 finding remains in the reviewed SPAKE2+ scope. Resume S10
with the restricted provider as the Apple enrollment PAKE implementation, while
keeping the separate iOS X.509 policy/runtime and real-device qualification
work explicitly open.
