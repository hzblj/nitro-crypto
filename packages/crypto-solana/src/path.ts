import {CryptoError} from '@hzblj/nitro-crypto/adapter'

export type SolanaAccountRequest =
  /** `m/44'/501'/{account}'/0'`, account 0 when left out: what Phantom, Solflare and `solana-keygen` derive. */
  | {readonly account?: number}
  /** Any SLIP-0010 path; every step must be hardened, as Ed25519 derivation requires. */
  | {readonly path: string}

const MAX_INDEX = 0x7fffffff

export const derivationPath = (request: SolanaAccountRequest): string => {
  if ('path' in request) {
    return request.path
  }

  const account = request.account ?? 0

  if (!Number.isInteger(account) || account < 0 || account > MAX_INDEX) {
    throw new CryptoError('INVALID_ARGUMENT', 'The account index is an integer from 0 to 2^31 - 1.')
  }

  return `m/44'/501'/${account}'/0'`
}
