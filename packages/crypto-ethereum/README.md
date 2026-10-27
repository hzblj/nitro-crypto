# @hzblj/crypto-ethereum

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-ethereum.svg)](https://www.npmjs.com/package/@hzblj/crypto-ethereum)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-ethereum.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Ethereum and every EVM chain for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto):
secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 messages and EIP-712 typed data with signer recovery,
legacy, EIP-2930, EIP-1559 and EIP-7702 transactions (contract creation and access lists included), EIP-7702
authorizations, ERC-20 call data, and a viem account. The keys stay in the native engine; this package is
TypeScript over it.

```sh
npx expo install @hzblj/nitro-crypto @hzblj/crypto-ethereum react-native-nitro-modules
```

```ts
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {createCryptoEngine} from '@hzblj/nitro-crypto'

const crypto = createCryptoEngine({adapters: [ethereumAdapter(), ethereumAdapter({id: 'base', chainId: 8453, name: 'Base'})]})
const wallet = await crypto.createEphemeralWallet()

const account = await wallet.deriveAccount({chain: 'ethereum', index: 0}) // m/44'/60'/0'/0/0
account.address // 0x… (EIP-55)
const signature = await account.signMessage({message: 'Hello from Expo'}) // EIP-191 personal_sign, 0x… (65 bytes)
await account.verifyMessage({message: 'Hello from Expo', signature}) // true

crypto.chains.ethereum.recoverMessageAddress({message: 'Hello from Expo', signature}) // the signer
crypto.chains.ethereum.validateAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed') // {valid, checksum: 'valid', normalized}
```

### One adapter per network

Every signature that can name a chain is bound to the adapter's chain id: a transaction, a typed data domain, an
EIP-7702 authorization. A request for another chain id is refused with `CHAIN_MISMATCH`, as wallets refuse it, so an
adapter configured for a test network never signs for mainnet. To sign on several networks, register one adapter per
network (the address is the same on each) and sign with the account of the network the request is for; a dApp asking
for a chain the app has no adapter for is a "switch network" prompt, not a signature.

```ts
try {
  await account.signTypedData(request)
} catch (error) {
  if (isCryptoError(error, 'CHAIN_MISMATCH')) {
    // the dApp asked for another network than this account's
  }
}
```

### Typed data (EIP-712)

`signTypedData` takes viem's shape, which is also `eth_signTypedData_v4`'s once its JSON is parsed:

```ts
const signature = await account.signTypedData({
  domain: {name: 'Permit2', chainId: 11155111, verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3'},
  types: {
    PermitSingle: [
      {name: 'details', type: 'PermitDetails'},
      {name: 'spender', type: 'address'},
      {name: 'sigDeadline', type: 'uint256'},
    ],
    PermitDetails: [
      {name: 'token', type: 'address'},
      {name: 'amount', type: 'uint160'},
      {name: 'expiration', type: 'uint48'},
      {name: 'nonce', type: 'uint48'},
    ],
  },
  primaryType: 'PermitSingle',
  message: {details: {token, amount, expiration, nonce}, spender, sigDeadline},
})

const {sepolia} = crypto.chains
sepolia.hashTypedData(typedData) // the digest signed: keccak256(0x1901 || domainSeparator || hashStruct(message))
sepolia.hashDomain({domain}) // the domain separator, as the contract's DOMAIN_SEPARATOR() returns it
sepolia.hashStruct({types, primaryType, data}) // hashStruct of any struct
sepolia.recoverTypedDataAddress({...typedData, signature}) // the signer, or undefined
sepolia.verifyTypedData({...typedData, address, signature}) // and account.verifyTypedData({...typedData, signature})
```

The whole of EIP-712: nested structs, arrays of any dimension (dynamic and fixed, of structs too), `bytes` and
`string` hashed, every `intN`, `uintN` and `bytesN` with its range or size checked. `EIP712Domain` is taken from
`types` when the dApp declares it (any of EIP-712's five fields, in the order declared), or derived from the fields
the domain has. Integers may be a `bigint`, a safe `number`, or decimal or `0x` text, as JSON-RPC payloads carry
them. Members the types do not declare are ignored, as viem, ethers and MetaMask ignore them (Seaport orders carry
one), so a review screen shows what the types declare: that is what is signed.

Refused, with `INVALID_ARGUMENT` (`INVALID_ADDRESS` for an address, `INVALID_ENCODING` for malformed hex): an unknown
type, a recursive one (a struct that contains itself, through arrays too), a struct named like an elementary type, a
missing member, a value of the wrong type or out of range, a fixed array of another length, an empty domain, and a
domain field EIP-712 does not define. Error messages name the struct and member, never a value. A domain with a
`chainId` other than the adapter's is `CHAIN_MISMATCH`, declared or not; a domain without one is signed, and binds
the signature to no chain.

### Transactions

Accounts sign transactions of four types for their adapter's chain id; fetching the nonce and fees and broadcasting
are the app's, over any JSON-RPC client:

```ts
const crypto = createCryptoEngine({adapters: [ethereumAdapter({id: 'sepolia', chainId: 11155111, name: 'Sepolia'})]})
const {erc20} = crypto.chains.sepolia
const account = await wallet.deriveAccount({chain: 'sepolia'})

// EIP-1559 (type 2), the default:
const {serialized, hash} = await account.signTransaction({
  to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  value: 10n ** 15n, // wei
  nonce, // eth_getTransactionCount(address, 'pending')
  gas: 21000n,
  maxFeePerGas, // base fee and tip together
  maxPriorityFeePerGas,
  accessList, // optional, from eth_createAccessList
})
// eth_sendRawTransaction(serialized); the receipt is eth_getTransactionReceipt(hash)

// Legacy (type 0), always with EIP-155 replay protection, and EIP-2930 (type 1) with an access list:
await account.signTransaction({type: 'legacy', to, value, nonce, gas, gasPrice})
await account.signTransaction({type: 'eip2930', to, data, nonce, gas, gasPrice, accessList})

// Contract creation: `to: null`, and the init code in `data`:
await account.signTransaction({to: null, data: bytecode, nonce, gas, maxFeePerGas, maxPriorityFeePerGas})

// An ERC-20 transfer is a call to the token contract, with value 0:
const data = erc20.transferData(recipient, 5_000_000n) // 5 USDC, 6 decimals
await account.signTransaction({to: usdc, data, nonce, gas, maxFeePerGas, maxPriorityFeePerGas})

// And a balance is an eth_call:
const balance = erc20.decodeUint256(await ethCall({data: erc20.balanceOfData(address), to: usdc}))
```

| `type` | | Fees | Access list | Contract creation |
| --- | --- | --- | --- | --- |
| `'legacy'` | 0, EIP-155 | `gasPrice` | No | Yes |
| `'eip2930'` | 1 | `gasPrice` | Yes | Yes |
| `'eip1559'` (or left out) | 2 | `maxFeePerGas`, `maxPriorityFeePerGas` | Yes | Yes |
| `'eip7702'` | 4 | `maxFeePerGas`, `maxPriorityFeePerGas` | Yes | No: `to` is required |

`to` is never left out: an address, or `null` to create a contract (with init code in `data`), so a forgotten
recipient is an error rather than a deployment. A request that mixes types (a `gasPrice` on an EIP-1559
transaction, an access list on a legacy one) is refused. `serializeTransaction(request)` returns the unsigned
transaction (its Keccak-256 is what is signed), and with a signature, the signed one. A signed transaction also
carries its `signature` (`r || s` and the y parity), as an air-gapped signer sends it back.

### EIP-7702: delegating an account's code

An authorization lets the account's address run a contract's code, with the account's balance and storage: whoever
controls that contract controls the account, so a wallet asks for it as it would for the key itself. A type 4
transaction carries one or more authorizations; whoever sends it pays for it, the authorizing account or a sponsor.

```ts
const authorization = await account.signAuthorization({
  address: delegate, // the contract delegated to; the zero address clears a delegation
  nonce: nonce + 1, // the account's nonce when it is processed: + 1 when this account also sends the transaction
}) // {address, chainId, nonce, signature}

await account.signTransaction({type: 'eip7702', to: account.address, data, nonce, gas, maxFeePerGas, maxPriorityFeePerGas, authorizationList: [authorization]})

sepolia.recoverAuthorizationAddress(authorization) // who authorized it, from a transaction's list or a request
sepolia.hashAuthorization({address, nonce}) // keccak256(0x05 || rlp([chainId, address, nonce])), to sign elsewhere
```

An authorization is for the adapter's chain id. Chain id 0 makes it valid on every chain, with the account's funds on
every chain behind it: it is refused (`CHAIN_MISMATCH`) unless the call says `allowAllChains: true` as well, which an
app sets only after the user has seen what it means. Authorizations already signed (for this chain or chain id 0) are
accepted in a transaction's list as they are.

### viem

`@hzblj/crypto-ethereum/viem` turns an account into a viem `LocalAccount`, so a wallet client signs in the engine:

```ts
import {toViemAccount} from '@hzblj/crypto-ethereum/viem'
import {createWalletClient, http} from 'viem'
import {sepolia} from 'viem/chains'

const client = createWalletClient({account: toViemAccount(account), chain: sepolia, transport: http()})
await client.sendTransaction({to, value})
await client.signTypedData(typedData)
await client.signAuthorization({contractAddress: delegate, executor: 'self'})
```

viem is an optional peer dependency (`^2.26.0`), needed only by this entry; the main entry never imports it. What it
signs is byte for byte what viem's `privateKeyToAccount` signs for the same key: `signMessage`, `signTypedData`,
`signTransaction` and `signAuthorization`, through the account's checks (chain id, typed data validation, no
unprotected legacy transactions, chain id 0 only with `toViemAccount(account, {allowAllChains: true})`). It also takes
viem's `nonceManager`.

- **No `sign({hash})`.** Signing a bare 32-byte hash is `eth_sign`: the hash shows nothing of what it commits to (a
  transaction, a permit, an authorization), so no wallet can show the user what they are signing, and it is the
  classic way to phish one. The account does not offer it, and its type says so. viem features that need it (some
  smart account owners) do not work with it.
- **Chains with their own serializer** (OP Stack chains such as Base and Optimism, Celo, zkSync) pass it to
  `signTransaction`. The account signs only what this adapter serializes: it runs the chain's serializer and requires
  the same bytes, unsigned before the key signs and signed before the result is returned. Standard transactions on OP
  Stack chains pass; a chain's own types (deposits, CIP-64, zkSync's EIP-712 transactions) are `UNSUPPORTED`.

### Signing elsewhere

For a key the app does not hold (an air-gapped signer, a hardware wallet), the chain reads and assembles what
travels between the two:

```ts
const {sepolia} = crypto.chains
sepolia.parseTransaction(unsigned) // the request in an unsigned transaction: what a signer shows before it signs
sepolia.recoverTransactionAddress({transaction: request, signature}) // who signed it, or undefined
sepolia.assembleTransaction(request, signature) // {serialized, hash, signature}: check the signer first
sepolia.addressFromPublicKey(publicKey) // compressed or uncompressed SEC1
```

`parseTransaction` reads every type the accounts sign, and returns it with every field present and its `type`
(`'legacy'`, `'eip2930'`, `'eip1559'`, `'eip7702'`), `to: null` for a contract creation. It is strict: canonical RLP
and integers, nothing after the fields, the adapter's chain id (`CHAIN_MISMATCH` otherwise), and for type 4 a
non-empty list of authorizations for this chain or chain id 0. A signed transaction, a legacy one without EIP-155,
and anything this package would serialize differently are `INVALID_ARGUMENT`; a blob transaction or an unknown type
is `UNSUPPORTED`. Serializing what it returns gives back the same bytes. `@hzblj/crypto-airgap-ethereum` carries
these over QR codes (ERC-4527).

| Request | Path |
| --- | --- |
| `{index}` (and `account`, both 0 by default) | `m/44'/60'/{account}'/0/{index}`, MetaMask's |
| `{path}` | Any BIP-32 path (Ledger Live: `m/44'/60'/{account}'/0/0`) |

| Configuration | |
| --- | --- |
| `id` | The id it registers under. One per EVM network: `ethereum`, `base`, `sepolia`. |
| `chainId` | The EIP-155 chain id, 1 by default. The address is the same on every network; the account carries the network. |
| `name` | For people, "Ethereum" by default. |

The adapter's `features` say what it does: `messageSigning`, `typedData`, `transactionSigning`,
`legacyTransactions`, `accessLists`, `contractCreation` and `setCodeTransactions` (EIP-7702) are `true`;
`blobTransactions` and `hashSigning` are `false`.

Signatures are byte-for-byte viem's for the same key and message (RFC 6979, lower S), and both libraries verify each
other's. Messages are text (signed as UTF-8) or raw bytes. `verifyMessage` and `verifyTypedData` are `false` for any
signature that does not recover to the account, including a malformed one. Typed data hashes and signatures, signed
transactions of every type and authorizations are byte-for-byte viem's too (EIP-712's and EIP-155's published
examples among the tests), and viem recovers their signers.

**Not in this version:**

- EIP-4844 blob transactions (type 3), and a chain's own transaction types (OP Stack deposits, Celo's CIP-64,
  zkSync's EIP-712 transactions).
- Signing a bare hash (`eth_sign`), on purpose: see above.
- Recursive EIP-712 types (a struct that contains itself), which EIP-712 allows and wallets rarely meet.
- Reading a signed transaction: `parseTransaction` reads the unsigned ones a signer is asked to sign.
- Smart contract signatures (ERC-1271, ERC-6492): verification is recovery, so it knows externally owned accounts
  only.
- Network access: nonces, fees, gas estimates, access lists from `eth_createAccessList`, broadcasting.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
