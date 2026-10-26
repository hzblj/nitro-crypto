/**
 * Every failure the package reports, as a `CryptoError` with a stable `code`. Native failures arrive as the engine's
 * status names (`NC_ERR_INVALID_LENGTH`) and are mapped here; nothing in a message ever contains an input value, so
 * no key, mnemonic or passphrase can reach a log through an error.
 */

export const CRYPTO_ERROR_CODES = [
  // From the engine
  'INVALID_ARGUMENT',
  'INVALID_LENGTH',
  'INVALID_PRIVATE_KEY',
  'INVALID_PUBLIC_KEY',
  'INVALID_SIGNATURE',
  'VERIFICATION_FAILED',
  'INVALID_PATH',
  'INVALID_MNEMONIC',
  'MNEMONIC_CHECKSUM',
  'INVALID_HANDLE',
  'HANDLE_LIMIT',
  'ENTROPY_UNAVAILABLE',
  'DERIVATION_FAILED',
  'INTERNAL',
  // From the facade
  'ABI_MISMATCH',
  'NATIVE_UNAVAILABLE',
  'DISPOSED',
  'INVALID_ENCODING',
  'INVALID_ADDRESS',
  'UNSUPPORTED',
  // From the adapter registry
  'DUPLICATE_ADAPTER',
  'MISSING_CAPABILITY',
  'INVALID_ADAPTER',
  'INVALID_CONFIG',
  'UNKNOWN_CHAIN',
] as const

export type CryptoErrorCode = (typeof CRYPTO_ERROR_CODES)[number]

const DEFAULT_MESSAGES: Record<CryptoErrorCode, string> = {
  ABI_MISMATCH: 'The native engine implements a different C ABI version than this package expects.',
  DERIVATION_FAILED: 'Key derivation produced an invalid key at this path.',
  DISPOSED: 'This key or wallet has been disposed.',
  DUPLICATE_ADAPTER: 'Two adapters share one id.',
  ENTROPY_UNAVAILABLE: 'The operating system did not provide secure random bytes.',
  HANDLE_LIMIT: 'Too many keys and seeds are alive in the engine.',
  INTERNAL: 'The engine failed internally.',
  INVALID_ADAPTER: 'An adapter does not satisfy the adapter contract.',
  INVALID_ADDRESS: 'The address is not valid.',
  INVALID_ARGUMENT: 'An argument is missing or not one the engine accepts.',
  INVALID_CONFIG: 'An adapter configuration is not valid.',
  INVALID_ENCODING: 'The text is not a valid encoding.',
  INVALID_HANDLE: 'The key or seed no longer exists in the engine.',
  INVALID_LENGTH: 'An input has a length the algorithm does not accept.',
  INVALID_MNEMONIC: 'The mnemonic has a word count BIP-39 does not define, or a word that is not in the English list.',
  INVALID_PATH: 'The derivation path is not valid for this scheme.',
  INVALID_PRIVATE_KEY: 'The private key is zero or not below the curve order.',
  INVALID_PUBLIC_KEY: 'The public key is not a valid point.',
  INVALID_SIGNATURE: 'The signature is malformed or not canonical.',
  MISSING_CAPABILITY: 'The engine lacks a capability an adapter requires.',
  MNEMONIC_CHECKSUM: 'The mnemonic checksum does not match.',
  NATIVE_UNAVAILABLE:
    'The nitro-crypto native module is not linked. It needs a development build (Expo Go does not include it).',
  UNKNOWN_CHAIN: 'No adapter is registered for this chain.',
  UNSUPPORTED: 'This operation is not supported here.',
  VERIFICATION_FAILED: 'The signature does not verify.',
}

export class CryptoError extends Error {
  readonly code: CryptoErrorCode

  constructor(code: CryptoErrorCode, message: string = DEFAULT_MESSAGES[code], options?: {cause?: unknown}) {
    super(message, options)
    this.name = 'CryptoError'
    this.code = code
  }
}

/** Whether `error` is a `CryptoError`, of `code` when given; narrows `error.code` to it. */
export const isCryptoError = <Code extends CryptoErrorCode = CryptoErrorCode>(
  error: unknown,
  code?: Code
): error is CryptoError & {readonly code: Code} =>
  error instanceof CryptoError && (code === undefined || error.code === code)

/** The engine's status names, as `include/nitro_crypto.h` defines them. */
const NATIVE_STATUSES: Record<string, CryptoErrorCode> = {
  NC_ERR_BUFFER_TOO_SMALL: 'INTERNAL',
  NC_ERR_DERIVATION_FAILED: 'DERIVATION_FAILED',
  NC_ERR_ENTROPY_UNAVAILABLE: 'ENTROPY_UNAVAILABLE',
  NC_ERR_HANDLE_LIMIT: 'HANDLE_LIMIT',
  NC_ERR_INTERNAL: 'INTERNAL',
  NC_ERR_INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  NC_ERR_INVALID_HANDLE: 'INVALID_HANDLE',
  NC_ERR_INVALID_LENGTH: 'INVALID_LENGTH',
  NC_ERR_INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  NC_ERR_INVALID_PATH: 'INVALID_PATH',
  NC_ERR_INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY',
  NC_ERR_INVALID_PUBLIC_KEY: 'INVALID_PUBLIC_KEY',
  NC_ERR_INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  NC_ERR_MNEMONIC_CHECKSUM: 'MNEMONIC_CHECKSUM',
  NC_ERR_VERIFICATION_FAILED: 'VERIFICATION_FAILED',
}

const STATUS_PATTERN = /NC_ERR_[A-Z_]+/

/**
 * A `CryptoError` for whatever native code threw. Nitro prefixes the native message with the method
 * ("`NitroCrypto.hash(...)`: NC_ERR_INVALID_LENGTH"); only the status name is read. An error without one (an
 * enum Nitro could not convert, say) is `INVALID_ARGUMENT`, and its own message is dropped.
 */
export const fromNativeError = (error: unknown): CryptoError => {
  if (error instanceof CryptoError) {
    return error
  }

  const status = error instanceof Error ? STATUS_PATTERN.exec(error.message)?.[0] : undefined
  const code = (status && NATIVE_STATUSES[status]) || (status ? 'INTERNAL' : 'INVALID_ARGUMENT')

  return new CryptoError(code, DEFAULT_MESSAGES[code])
}

/** Runs a native call and rethrows its failure as a `CryptoError`. */
export const native = <T>(call: () => T): T => {
  try {
    return call()
  } catch (error) {
    throw fromNativeError(error)
  }
}

export const nativeAsync = async <T>(call: () => Promise<T>): Promise<T> => {
  try {
    return await call()
  } catch (error) {
    throw fromNativeError(error)
  }
}
