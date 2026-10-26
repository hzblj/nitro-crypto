# @hzblj/crypto-ethereum

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-ethereum.svg)](https://www.npmjs.com/package/@hzblj/crypto-ethereum)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-ethereum.svg)](https://github.com/hzblj/nitro-crypto/blob/main/LICENSE)

Ethereum and every EVM chain for [`@hzblj/nitro-crypto`](https://www.npmjs.com/package/@hzblj/nitro-crypto):
secp256k1 accounts at BIP-44 paths, EIP-55 addresses, EIP-191 message signatures and signer recovery, EIP-1559
transactions and ERC-20 call data. The keys stay in the native engine; this package is TypeScript over it.

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

### Transactions

Accounts sign EIP-1559 (type 2) transactions for their adapter's chain id; fetching the nonce and fees and
broadcasting are the app's, over any JSON-RPC client:

```ts
const crypto = createCryptoEngine({adapters: [ethereumAdapter({id: 'sepolia', chainId: 11155111, name: 'Sepolia'})]})
const {erc20} = crypto.chains.sepolia
const account = await wallet.deriveAccount({chain: 'sepolia'})

const {serialized, hash} = await account.signTransaction({
  to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  value: 10n ** 15n, // wei
  nonce, // eth_getTransactionCount(address, 'pending')
  gas: 21000n,
  maxFeePerGas, // base fee and tip together
  maxPriorityFeePerGas,
})
// eth_sendRawTransaction(serialized); the receipt is eth_getTransactionReceipt(hash)

// An ERC-20 transfer is a call to the token contract, with value 0:
const data = erc20.transferData(recipient, 5_000_000n) // 5 USDC, 6 decimals
await account.signTransaction({to: usdc, data, nonce, gas, maxFeePerGas, maxPriorityFeePerGas})

// And a balance is an eth_call:
const balance = erc20.decodeUint256(await ethCall({data: erc20.balanceOfData(address), to: usdc}))
```

A transaction carries the adapter's chain id; a request naming another is refused, so an adapter configured for a
test network never signs for mainnet. `serializeTransaction(request)` returns the unsigned envelope (its Keccak-256 is
what is signed), and with a signature, the signed one.

| Request | Path |
| --- | --- |
| `{index}` (and `account`, both 0 by default) | `m/44'/60'/{account}'/0/{index}`, MetaMask's |
| `{path}` | Any BIP-32 path (Ledger Live: `m/44'/60'/{account}'/0/0`) |

| Configuration | |
| --- | --- |
| `id` | The id it registers under. One per EVM network: `ethereum`, `base`, `sepolia`. |
| `chainId` | The EIP-155 chain id, 1 by default. The address is the same on every network; the account carries the network. |
| `name` | For people, "Ethereum" by default. |

Signatures are byte-for-byte viem's for the same key and message (RFC 6979, lower S), and both libraries verify each
other's. Messages are text (signed as UTF-8) or raw bytes. `verifyMessage` is `false` for any signature that does not
recover to the account, including a malformed one. Signed transactions are byte-for-byte viem's too, and viem recovers
their sender.

**Not in this version:** EIP-712 typed data, legacy (type 0) and EIP-2930 (type 1) transactions, access lists,
contract creation, and any network access (nonces, fees, gas estimates, broadcasting). The adapter's `features` say
so.

[Documentation](https://github.com/hzblj/nitro-crypto#readme) · [Security](https://github.com/hzblj/nitro-crypto/blob/main/SECURITY.md)
