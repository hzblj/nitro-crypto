# 7. Extended public keys leave the engine, the master's never

Accepted. Amends [0004](0004-secrets-behind-handles.md) and [0006](0006-air-gap-as-data.md).

## Context

A watch-only wallet shows every address of an account and builds transactions from any of them; the signer only
signs. To do that without asking the signer for each address, it needs the account's extended public key: the
account's public key and its BIP-32 chain code, from which it derives every receiving and change address (public
derivation, CKDpub). Sparrow and other Bitcoin coordinators pair with exactly that (`crypto-account`), MetaMask's QR
hardware wallets too (`crypto-hdkey` at `m/44'/60'/0'`), and Keystone and OneKey share theirs that way.

The engine exported neither: no chain code left it, and it could not derive a public key from someone else's
extended key. So this wallet could pair only with itself, one address per chain, and watch no hardware wallet's
account (ADR 0006's consequences said so).

A chain code is not a private key, but it is not harmless either. With an extended public key, the private key of
any non-hardened child gives the parent's private key away (the child's is the parent's plus a tweak the chain code
determines). And it is a privacy grant: whoever holds it sees every address of the account.

## Decision

- **Two functions, public data only.** `nc_seed_extended_public(seed, path)` writes the extended public key at a
  path below a seed handle: depth, parent fingerprint, child number, chain code and compressed public key, the 74
  bytes of BIP-32's serialization without its version (a network's choice, made in TypeScript). The private key it
  derives along the way stays on the stack and is zeroed, as every derivation's is. `nc_bip32_public_derive(extended,
  path)` is CKDpub: an extended public key down a path of non-hardened steps, stateless, with no handle and no secret.
- **Never the master's.** A path must have at least one step; `m` is `INVALID_PATH`. The master's chain code with any
  one leaked private key below it in a non-hardened step is the whole wallet; an account's (`m/84'/0'/0'`, hardened
  down to the account, as every standard path is) is that account at most, the risk every wallet that pairs this way
  takes.
- **Still no private key leaves.** ADR 0004's rule holds for every private key and seed; this ADR adds chain codes at
  depth one or more, and nothing else. The facade exposes them as `wallet.extendedPublicKey(path)` (and
  `KeySource.extendedPublicKey` for adapters) and `crypto.bip32.derivePublic(key, path)`, as structured values
  (`ExtendedPublicKey`), not as xpub text.
- **Additive:** two functions and two capability bits, `bip32-extended-public` (bit 14) and
  `bip32-public-derivation` (bit 15). The ABI version stays 1. An adapter that needs public derivation checks the
  capability and says `UNSUPPORTED` without it.
- **Held to the reference.** BIP-32's published test vectors (the xpubs of both chains, at every depth), the BIP-84
  keys in the C harness, and parity with `@scure/bip32` on random paths in the TypeScript tests.

## Consequences

- The air-gap packages pair with account keys: `accountKey` in `@hzblj/crypto-airgap-bitcoin` (for Sparrow's
  `crypto-account`) and `@hzblj/crypto-airgap-ethereum` (MetaMask's `crypto-hdkey`, as Keystone and OneKey write it),
  watch any address of an account key a hardware wallet shares, and sign for any address of the account a request
  names, each checked against the request (`signRequest`).
- An app that shows an extended public key hands out its account's history. The example says so where it shows one.
- Solana and other Ed25519 accounts (SLIP-0010, hardened only) have no public derivation: they still pair one
  address at a time.
