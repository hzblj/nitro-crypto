# 2. secp256k1 from libsecp256k1, with an 8-bit verification table and renamed symbols

Accepted.

## Context

Zig's standard library has secp256k1 (`std.crypto.ecc.Secp256k1`, `std.crypto.sign.ecdsa`), but it cannot serve
Ethereum or Bitcoin:

- its ECDSA nonce is deterministic but not RFC 6979 (it hashes in a noise field), so its signatures differ from every
  other wallet's for the same key and message;
- it neither produces nor enforces lower-S signatures, which Ethereum (EIP-2) and Bitcoin policy require;
- it has no public key recovery, which Ethereum's `personal_sign` verification and `ecrecover` are built on.

## Decision

Use [bitcoin-core/libsecp256k1](https://github.com/bitcoin-core/secp256k1) v0.8.0, the library Bitcoin Core signs
with: constant-time signing with context blinding, RFC 6979, lower S, and the recovery module. Zig compiles it from
the release tarball, pinned by content hash in `build.zig.zon`; only the recovery module is enabled.

- **One context, preallocated and randomized** with OS entropy on first use, for operations on secrets; the static
  context for parsing and verification.
- **Every public symbol renamed** `nc_secp256k1_*` (`src/curves/secp256k1_prefix.h`, force-included), so an app that
  also links libsecp256k1 (a wallet SDK, another module) links both. `yarn engine:verify` fails if an archive exports
  any name outside `nc_*`.
- **Our own default callbacks**: misuse is reported by return value (arguments are checked first anyway); an internal
  consistency failure aborts.
- **`ECMULT_WINDOW_SIZE=8`** instead of upstream's 15. Measured on Apple Silicon, ReleaseFast:

  | Window | Tables | verify | recover | Static archive |
  | --- | --- | --- | --- | --- |
  | 15 (upstream default) | 1 MiB | 26.8 µs | 28.2 µs | 2.6 MB |
  | 11 | 64 KiB | 27.8 µs | 29.0 µs | |
  | 8 (chosen) | 8 KiB | 28.7 µs | 30.5 µs | 1.6 MB |
  | 6 | 2 KiB | 30.6 µs | 31.6 µs | |
  | 4 | 512 B | 33.3 µs | 34.7 µs | |

  Window 8 is the knee: about 7% slower verification for a megabyte less in every slice of every app. Wallets verify
  rarely; apps ship always. `zig build -Decmult-window=15` restores the default for a host that verifies in bulk.

## Consequences

- Signatures are byte-for-byte those of viem and `@noble/curves` (tested), so any Ethereum or Bitcoin verifier accepts
  them.
- Verification and recovery refuse the upper-S twin of a valid signature (`INVALID_SIGNATURE`): stricter than generic
  ECDSA (Wycheproof's "valid" upper-S cases are refused, and the suite's test says so), as strict as the chains.
- Updating libsecp256k1 is: a new tag and hash in `build.zig.zon`, regenerating the prefix list from `nm` if the
  release adds symbols, and rerunning every vector and parity test.
