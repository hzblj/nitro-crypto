import {base58, bytes, CryptoError, utf8} from '@hzblj/nitro-crypto/adapter'

import {addressBytes, type SolanaAddress} from './address'
import {isOnCurveBytes} from './curve'
import {ASSOCIATED_TOKEN_PROGRAM, TOKEN_PROGRAM} from './programs'

export type Sha256 = (data: Uint8Array) => Uint8Array

/** A program-derived address and the bump seed that put it off the curve. */
export type ProgramAddress = {readonly address: SolanaAddress; readonly bump: number}

const MARKER = utf8.encode('ProgramDerivedAddress')
const MAX_SEEDS = 16
const MAX_SEED_LENGTH = 32

/** The address `seeds` give under `programId`, or `undefined` when the digest is on the curve (it has a key). */
export const createProgramAddress = (
  seeds: readonly Uint8Array[],
  programId: string,
  sha256: Sha256
): SolanaAddress | undefined => {
  if (seeds.length > MAX_SEEDS) {
    throw new CryptoError('INVALID_ARGUMENT', `A program address takes at most ${MAX_SEEDS} seeds.`)
  }

  if (seeds.some(seed => seed.length > MAX_SEED_LENGTH)) {
    throw new CryptoError('INVALID_ARGUMENT', `A program address seed is at most ${MAX_SEED_LENGTH} bytes.`)
  }

  const digest = sha256(bytes.concat(...seeds, addressBytes(programId, 'program'), MARKER))

  return isOnCurveBytes(digest) ? undefined : base58.encode(digest)
}

/** The canonical program-derived address: the first bump, from 255 down, that puts the digest off the curve. */
export const findProgramAddress = (seeds: readonly Uint8Array[], programId: string, sha256: Sha256): ProgramAddress => {
  if (seeds.length >= MAX_SEEDS) {
    throw new CryptoError('INVALID_ARGUMENT', `A program address takes at most ${MAX_SEEDS - 1} seeds and a bump.`)
  }

  for (let bump = 255; bump > 0; bump--) {
    const address = createProgramAddress([...seeds, Uint8Array.of(bump)], programId, sha256)

    if (address !== undefined) {
      return {address, bump}
    }
  }

  throw new CryptoError('DERIVATION_FAILED', 'No bump seed gives these seeds an address off the curve.')
}

export type AssociatedTokenRequest = {
  /** The wallet that owns the token account. */
  readonly owner: string
  readonly mint: string
  /** The mint's token program: `TOKEN_PROGRAM` unless stated, `TOKEN_2022_PROGRAM` for Token-2022 mints. */
  readonly tokenProgram?: string
}

/** The associated token account of `owner` for `mint`: seeds owner, token program and mint, under the ATA program. */
export const associatedTokenAddress = (
  {mint, owner, tokenProgram = TOKEN_PROGRAM}: AssociatedTokenRequest,
  sha256: Sha256
): SolanaAddress =>
  findProgramAddress(
    [addressBytes(owner, 'owner'), addressBytes(tokenProgram, 'token program'), addressBytes(mint, 'mint')],
    ASSOCIATED_TOKEN_PROGRAM,
    sha256
  ).address
