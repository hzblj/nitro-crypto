# Adding an adapter

A chain whose curves and hashes the engine already has is one TypeScript file: no change to the engine, to
`@hzblj/nitro-crypto`, or to any other adapter. The example app proves it with TRON
([`apps/example/src/features/debug/chains/tron.ts`](../apps/example/src/features/debug/chains/tron.ts)), registered beside the three published
adapters and tested against independent libraries in [`apps/example/test/chains.test.ts`](../apps/example/test/chains.test.ts).

## 1. Check the engine has what the chain needs

| Capability | What it is |
| --- | --- |
| `random` | OS randomness |
| `sha256`, `sha512`, `keccak256`, `ripemd160` | Hashes (`keccak256` is Ethereum's Keccak, not SHA3-256) |
| `hmac-sha256`, `hmac-sha512` | HMAC |
| `secp256k1-ecdsa`, `secp256k1-recovery` | ECDSA with RFC 6979 nonces and lower S; public key recovery |
| `ed25519` | RFC 8032 |
| `bip39` | Mnemonics and seeds |
| `bip32-secp256k1` | BIP-32 derivation, hardened and normal steps |
| `slip10-ed25519` | SLIP-0010 derivation for Ed25519, hardened steps only |
| `mnemonic-generate` | A fresh BIP-39 mnemonic handed out for backup (`crypto.mnemonic.generate`); no adapter needs it |
| `bip32-extended-public` | An account's extended public key (`keys.extendedPublicKey`), never the master's (ADR 0007) |
| `bip32-public-derivation` | Public derivation from an extended public key (`bip32.derivePublic`), non-hardened steps only |

TRON needs `bip32-secp256k1`, `keccak256` and `sha256` (for Base58Check): all there. If yours needs something that is
not (Schnorr for Taproot, sr25519 for Polkadot, Blake2b for Cardano), see "When the engine lacks a primitive" below.

## 2. Write the adapter

Import only from `@hzblj/nitro-crypto/adapter`: it is the contract, the shared encodings and the error type, and it
loads no native code.

```ts
import {base58check, defineAdapter, type AdapterContext, type KeySource} from '@hzblj/nitro-crypto/adapter'

export const tronAdapter = () =>
  defineAdapter({
    id: 'tron',
    name: 'TRON',
    version: '1.0.0',
    curve: 'secp256k1',
    requires: ['keccak256', 'sha256', 'bip32-secp256k1'],
    formats: {address: ['base58check-41'], signature: []},
    features: {messageSigning: false, transactionSigning: false},
    create: (context: AdapterContext) => ({
      deriveAccount: async (keys: KeySource, {account = 0}: {account?: number}) => {
        const key = keys.deriveKey('bip32', `m/44'/195'/${account}'/0/0`)
        const payload = new Uint8Array(21)
        payload[0] = 0x41
        payload.set(context.hash.keccak256(key.publicKey('uncompressed').subarray(1)).subarray(12), 1)
        return {address: base58check.encode(payload, context.hash.sha256), chain: 'tron' as const, path: key.path ?? ''}
      },
      validateAddress: address => {/* Base58Check, 21 bytes, prefix 0x41 */},
    }),
  })
```

What each part is for:

- **`id`** is how the chain is addressed (`crypto.chains.tron`, `deriveAccount({chain: 'tron'})`). Lowercase
  letters, digits and dashes. Two adapters may not share one; to register the same chain twice (mainnet and a
  testnet), take the id from the configuration.
- **`requires`** is checked when the engine is created: an engine without one of them refuses the adapter with
  `MISSING_CAPABILITY`, naming it, instead of failing later on a missing operation.
- **`features`** says what the adapter does and does not do. Say `false` rather than leaving a flag out: the example
  app shows these, and an app can branch on them.
- **`create`** runs once, with the engine's stateless primitives and its info. Close over `context`; never import a
  native module.
- **`deriveAccount`** receives a `KeySource`, not the seed: `deriveKey(scheme, path)` returns a key that the wallet
  owns and disposes with itself. Return whatever your chain's account is; its type flows to the caller.
- **`validateAddress`** returns `{valid: true, normalized}` or `{valid: false, reason}`; add your chain's own fields
  to the valid branch (Ethereum adds `checksum`, Bitcoin `type` and `scriptPubKey`).

Anything else on the client (`recoverMessageAddress`, `checksumAddress`) is yours to add, and typed by the client.

### A configurable id needs `NoInfer`

If your factory takes the id from its configuration, annotate its return type with `NoInfer`:

```ts
export const myAdapter = <const Id extends string = 'mine'>(
  config: {id?: Id} = {}
): ChainAdapter<NoInfer<Id>, MyChain<NoInfer<Id>>> => …
```

Without it, a call inside `createCryptoEngine({adapters: [myAdapter()]})` infers `Id` from the array's contextual
type (`string`) instead of taking the default, and `crypto.chains.mine` loses its type. The published adapters all do
this.

## 3. Test it against the real engine

`@hzblj/nitro-crypto/testing` runs the same Zig engine, compiled to WebAssembly, behind the same facade, in Node,
Jest or Vitest:

```ts
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

const crypto = createTestCryptoEngine({adapters: [tronAdapter()]})
const wallet = await crypto.createEphemeralWallet({mnemonic: 'abandon abandon … about'})
assert.equal((await wallet.deriveAccount({chain: 'tron'})).address, 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH')
```

Test against the chain's published vectors, and against an independent implementation on random inputs: each adapter
here does both (viem for Ethereum, `@scure/btc-signer` and BIP-84 for Bitcoin, `@solana/kit` for Solana).

## 4. Register it

```ts
createCryptoEngine({adapters: [ethereumAdapter(), tronAdapter()]})
```

That is the whole integration. Publishing it as a package means a `peerDependency` on `@hzblj/nitro-crypto`, like the
three here.

## When the engine lacks a primitive

A new curve, hash or derivation scheme is an addition to the engine, never a chain-specific branch in it:

1. Implement it in `packages/zig-engine-crypto/src`, from a reviewed implementation (as secp256k1 comes from
   libsecp256k1) or the standard's reference, with its published vectors in `test/vectors.zig` and, where one
   exists, a Wycheproof suite.
2. Add its function to `include/nitro_crypto.h` and `src/abi/c_api.zig`, and a capability bit (`NC_CAP_…`,
   `src/abi/version.zig`). New functions and bits are additive: the ABI version does not change, and older hosts
   ignore what they do not know.
3. Expose it in the Nitro spec, the C++ bridge, the WebAssembly host and the facade's primitives, and add its name
   to `CAPABILITIES` in `engine/info.ts`.
4. Then write the adapter as above, listing the new capability in `requires`.
