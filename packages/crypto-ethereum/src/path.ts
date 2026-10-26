import {CryptoError} from '@hzblj/nitro-crypto/adapter'

export type EthereumAccountRequest =
  /** BIP-44 `m/44'/60'/{account}'/0/{index}`, both 0 when left out: what MetaMask and most wallets derive. */
  | {readonly account?: number; readonly index?: number}
  /** Any BIP-32 path, for wallets that use another convention (Ledger Live: `m/44'/60'/{account}'/0/0`). */
  | {readonly path: string}

const MAX_INDEX = 0x7fffffff

const index = (value: number | undefined, name: string): number => {
  const resolved = value ?? 0

  if (!Number.isInteger(resolved) || resolved < 0 || resolved > MAX_INDEX) {
    throw new CryptoError('INVALID_ARGUMENT', `The ${name} index is an integer from 0 to 2^31 - 1.`)
  }

  return resolved
}

export const derivationPath = (request: EthereumAccountRequest): string =>
  'path' in request
    ? request.path
    : `m/44'/60'/${index(request.account, 'account')}'/0/${index(request.index, 'address')}`
