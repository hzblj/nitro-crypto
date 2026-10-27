import type {HybridObject} from 'react-native-nitro-modules'

/**
 * The native boundary, one Hybrid Object per kind of thing the engine holds. Nitrogen generates the C++ specs
 * from this file; `cpp/` implements them over the engine's C ABI. Everything here is binary and chain-agnostic:
 * the TypeScript facade in `src/engine` is what applications and adapters use.
 *
 * Errors thrown across it carry the engine's status name (`NC_ERR_INVALID_LENGTH`), never an input value.
 */

type Native = {android: 'c++'; ios: 'c++'}

/** A hash the engine computes. `keccak256` is Ethereum's Keccak-256, not NIST SHA3-256. */
export type HashAlgorithm = 'sha256' | 'sha512' | 'keccak256' | 'ripemd160'

export type HmacAlgorithm = 'sha256' | 'sha512'

export type Curve = 'secp256k1' | 'ed25519'

/** BIP-32 derives secp256k1 keys; SLIP-0010 derives Ed25519 keys and takes hardened steps only. */
export type DerivationScheme = 'bip32' | 'slip10'

/**
 * A private key inside the engine. JavaScript holds this object, never the key's bytes. `dispose()` (from
 * `HybridObject`) zeroizes the key; Nitro then detaches the object, so the facade tracks disposal itself.
 */
export interface NitroKey extends HybridObject<Native> {
  readonly curve: Curve
  /** secp256k1: SEC1, compressed (33 bytes) or uncompressed (65). Ed25519: 32 bytes, `compressed` ignored. */
  getPublicKey(compressed: boolean): ArrayBuffer
  /**
   * secp256k1: `data` is a 32-byte digest; returns 65 bytes, `r || s || recovery id`, with an RFC 6979 nonce
   * and a lower-S `s`. Ed25519: `data` is the message; returns the 64-byte RFC 8032 signature.
   */
  sign(data: ArrayBuffer): ArrayBuffer
  /** secp256k1 only: the BIP-340 x-only public key, 32 bytes. */
  getXOnlyPublicKey(): ArrayBuffer
  /**
   * secp256k1 only: a BIP-340 Schnorr signature of `message` (any length), 64 bytes, with fresh auxiliary randomness
   * from the OS.
   */
  signSchnorr(message: ArrayBuffer): ArrayBuffer
  /**
   * secp256k1 only: BIP-341's key path, a Schnorr signature of the 32-byte sighash `message` by the key tweaked with
   * `merkleRoot` (32 bytes), or with no script tree when `merkleRoot` is empty (BIP-86).
   */
  signTaproot(message: ArrayBuffer, merkleRoot: ArrayBuffer): ArrayBuffer
}

/** A BIP-39 seed inside the engine. Keys are derived from it; the seed itself never leaves. */
export interface NitroSeed extends HybridObject<Native> {
  /** The BIP-32 fingerprint of its secp256k1 master key: a public, stable name for the seed. */
  readonly fingerprint: number
  /** The key at `path` ("m/44'/60'/0'/0/0"). */
  deriveKey(scheme: DerivationScheme, path: string): NitroKey
  /**
   * The BIP-32 extended public key at `path` (at least one step), 74 bytes: depth, parent fingerprint, child number,
   * chain code, compressed public key. Public: no private key leaves (docs/adr/0007).
   */
  extendedPublicKey(path: string): ArrayBuffer
}

/** The engine. One per runtime, created by name through `NitroModules`. */
export interface NitroCrypto extends HybridObject<Native> {
  /** The C ABI version the linked engine implements. */
  readonly abiVersion: number
  readonly engineVersion: string
  /** What the engine was built with, for people: "zig 0.16.0, libsecp256k1 0.8.0, ecmult window 8". */
  readonly buildInfo: string
  /** The capability names the engine reports, such as `keccak256` and `slip10-ed25519`. */
  readonly capabilities: string[]
  /** How many seeds and keys are alive in the engine: a leak check. */
  readonly liveHandles: number

  /** Bytes from the operating system's CSPRNG. Throws rather than return anything weaker. */
  randomBytes(length: number): ArrayBuffer
  hash(algorithm: HashAlgorithm, data: ArrayBuffer): ArrayBuffer
  /** `hash` on a background thread, for payloads too large to hash on the JS thread. */
  hashAsync(algorithm: HashAlgorithm, data: ArrayBuffer): Promise<ArrayBuffer>
  hmac(algorithm: HmacAlgorithm, key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer

  secp256k1ConvertPublicKey(publicKey: ArrayBuffer, compressed: boolean): ArrayBuffer
  /** `false` when the signature does not verify; throws when an input is malformed or `s` is in the upper half. */
  secp256k1Verify(publicKey: ArrayBuffer, digest: ArrayBuffer, signature: ArrayBuffer): boolean
  secp256k1Recover(digest: ArrayBuffer, signature: ArrayBuffer, compressed: boolean): ArrayBuffer
  /**
   * BIP-340: `false` when the signature does not verify (a malformed one included); throws when the 32-byte x-only key
   * is not on the curve or a length is wrong.
   */
  secp256k1SchnorrVerify(publicKey: ArrayBuffer, message: ArrayBuffer, signature: ArrayBuffer): boolean
  /**
   * BIP-341's output key for an internal key (x-only 32 bytes, or SEC1) and the merkle root of its script tree (32
   * bytes, or empty for none): compressed, 33 bytes, its prefix the parity.
   */
  secp256k1TaprootTweak(publicKey: ArrayBuffer, merkleRoot: ArrayBuffer): ArrayBuffer
  /** `false` when the signature does not verify; throws when an input is malformed. */
  ed25519Verify(publicKey: ArrayBuffer, message: ArrayBuffer, signature: ArrayBuffer): boolean
  /** BIP-32 public derivation (non-hardened steps) of a 74-byte extended public key down `path` ("m/0/5"). */
  bip32DerivePublic(extendedPublicKey: ArrayBuffer, path: string): ArrayBuffer

  /** Throws `NC_ERR_INVALID_MNEMONIC` or `NC_ERR_MNEMONIC_CHECKSUM`. Takes NFKD-normalized UTF-8. */
  validateMnemonic(mnemonic: ArrayBuffer): void
  /**
   * A fresh mnemonic of `wordCount` words from the OS CSPRNG, as UTF-8 bytes (lowercase ASCII, single spaces), for
   * the user to write down. The engine keeps no copy; the facade decodes it and overwrites these bytes.
   */
  generateMnemonic(wordCount: number): ArrayBuffer
  /** A seed from a fresh mnemonic of `wordCount` words. Runs PBKDF2 on a background thread. */
  generateSeed(wordCount: number, passphrase: ArrayBuffer): Promise<NitroSeed>
  /** A seed from a known mnemonic: a restored wallet, or a published test vector. Runs PBKDF2 on a background thread. */
  seedFromMnemonic(mnemonic: ArrayBuffer, passphrase: ArrayBuffer): Promise<NitroSeed>

  generateKey(curve: Curve): NitroKey
  /** Raw secret material in: a 32-byte secp256k1 private key or Ed25519 seed. There is no way back out. */
  importKey(curve: Curve, secret: ArrayBuffer): NitroKey
}
