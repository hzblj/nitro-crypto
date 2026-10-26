import {bech32, bytes, CryptoError} from '@hzblj/nitro-crypto/adapter'

/** A witness program and its version: what a SegWit address encodes. */
export type WitnessProgram = {readonly version: number; readonly program: Uint8Array}

const invalid = (message: string) => new CryptoError('INVALID_ADDRESS', message)

/** BIP-141's and BIP-350's rules for a program: 2 to 40 bytes, and 20 or 32 for version 0. */
const checkProgram = ({program, version}: WitnessProgram) => {
  if (!Number.isInteger(version) || version < 0 || version > 16) {
    throw invalid('A witness version is 0 to 16.')
  }

  if (program.length < 2 || program.length > 40) {
    throw invalid('A witness program is 2 to 40 bytes.')
  }

  if (version === 0 && program.length !== 20 && program.length !== 32) {
    throw invalid('A version 0 witness program is 20 or 32 bytes.')
  }
}

/** Version 0 is Bech32 (BIP-173); every later version is Bech32m (BIP-350). */
const variantOf = (version: number) => (version === 0 ? 'bech32' : 'bech32m')

export const encodeSegwit = (hrp: string, witness: WitnessProgram): string => {
  checkProgram(witness)

  return bech32.encode(hrp, [witness.version, ...bech32.toWords(witness.program)], variantOf(witness.version))
}

/** Decodes and checks a SegWit address; `hrp` is the network's, which the address must carry. */
export const decodeSegwit = (hrp: string, address: string): WitnessProgram => {
  const decoded = bech32.decode(address)

  if (decoded.hrp !== hrp) {
    throw invalid(`A ${hrp} address starts with "${hrp}1".`)
  }

  const [version, ...data] = decoded.words

  if (version === undefined) {
    throw invalid('A SegWit address has a witness version.')
  }

  if (decoded.variant !== variantOf(version)) {
    throw invalid(`A version ${version} address uses ${variantOf(version)}, not ${decoded.variant}.`)
  }

  const witness = {program: bech32.fromWords(data), version}
  checkProgram(witness)

  return witness
}

/** The output script a witness program locks to: OP_n, then a push of the program. */
export const witnessScript = ({program, version}: WitnessProgram): Uint8Array =>
  bytes.concat(Uint8Array.of(version === 0 ? 0 : 0x50 + version, program.length), program)
