import {type AddressValidation, base58check, bech32, CryptoError, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import type {BitcoinNetwork} from './networks'
import {decodeSegwit, encodeSegwit, type WitnessProgram, witnessScript} from './segwit'

export type Hash = (data: Uint8Array) => Uint8Array

/** The kinds of address this adapter recognizes. It derives only `p2wpkh`; the rest it validates. */
export type BitcoinAddressType = 'p2wpkh' | 'p2wsh' | 'p2tr' | 'witness' | 'p2pkh' | 'p2sh'

export type BitcoinAddressValidation =
  | (AddressValidation & {
      readonly valid: true
      readonly type: BitcoinAddressType
      /** The script that pays this address. */
      readonly scriptPubKey: Uint8Array
    })
  | (AddressValidation & {readonly valid: false})

/** HASH160: RIPEMD-160 of SHA-256, which a P2WPKH address commits to. */
export const hash160 = (data: Uint8Array, sha256: Hash, ripemd160: Hash) => ripemd160(sha256(data))

/** The native SegWit (P2WPKH, BIP-84) address of a compressed public key. */
export const p2wpkhAddress = (publicKey: Uint8Array, network: BitcoinNetwork, sha256: Hash, ripemd160: Hash) => {
  if (publicKey.length !== 33) {
    throw new CryptoError('INVALID_PUBLIC_KEY', 'P2WPKH commits to a compressed (33-byte) public key.')
  }

  const witness = {program: hash160(publicKey, sha256, ripemd160), version: 0}

  return {address: encodeSegwit(network.bech32, witness), scriptPubKey: witnessScript(witness)}
}

const segwitType = ({program, version}: WitnessProgram): BitcoinAddressType => {
  if (version === 0) {
    return program.length === 20 ? 'p2wpkh' : 'p2wsh'
  }

  return version === 1 && program.length === 32 ? 'p2tr' : 'witness'
}

/** P2PKH and P2SH: `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` and `OP_HASH160 <20> OP_EQUAL`. */
const legacyScript = (type: 'p2pkh' | 'p2sh', hash: Uint8Array) =>
  type === 'p2pkh' ? Uint8Array.of(0x76, 0xa9, 20, ...hash, 0x88, 0xac) : Uint8Array.of(0xa9, 20, ...hash, 0x87)

const validateLegacy = (address: string, network: BitcoinNetwork, sha256: Hash): BitcoinAddressValidation => {
  const payload = base58check.decode(address, sha256)

  if (payload.length !== 21) {
    return {reason: 'A legacy address carries a version byte and a 20-byte hash.', valid: false}
  }

  const type = payload[0] === network.pubKeyHash ? 'p2pkh' : payload[0] === network.scriptHash ? 'p2sh' : undefined

  if (!type) {
    return {reason: `Not a ${network.name} address.`, valid: false}
  }

  return {normalized: address, scriptPubKey: legacyScript(type, payload.subarray(1)), type, valid: true}
}

/** The human-readable part, when `address` is Bech32 or Bech32m at all. */
const bech32Prefix = (address: string): string | undefined => {
  try {
    return bech32.decode(address).hrp
  } catch {
    return undefined
  }
}

/**
 * Any address a wallet on `network` can pay: SegWit of every version (Bech32 or Bech32m, as BIP-350 requires) and
 * legacy Base58Check. A valid address of another network is invalid here, with a reason that says so.
 */
export const validateAddress = (address: string, network: BitcoinNetwork, sha256: Hash): BitcoinAddressValidation => {
  try {
    const prefix = bech32Prefix(address)

    if (prefix !== undefined && prefix !== network.bech32) {
      return {
        reason: `Not a ${network.name} address: it is for "${prefix}", ${network.name} is "${network.bech32}".`,
        valid: false,
      }
    }

    if (prefix !== undefined || address.toLowerCase().startsWith(`${network.bech32}1`)) {
      const witness = decodeSegwit(network.bech32, address)

      return {
        normalized: address.toLowerCase(),
        scriptPubKey: witnessScript(witness),
        type: segwitType(witness),
        valid: true,
      }
    }

    return validateLegacy(address, network, sha256)
  } catch (error) {
    if (isCryptoError(error, 'INVALID_ADDRESS') || isCryptoError(error, 'INVALID_ENCODING')) {
      return {reason: error.message, valid: false}
    }

    throw error
  }
}
