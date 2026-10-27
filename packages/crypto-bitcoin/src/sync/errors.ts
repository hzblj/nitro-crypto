/**
 * Every failure of `@hzblj/crypto-bitcoin/sync`, as a `SyncError` with a stable `code`. Messages say what went wrong
 * without quoting addresses or keys: a log of a wallet's errors should not be a list of its addresses. A node's reason
 * for refusing a broadcast is kept (it names a rule, not the wallet).
 */

export const SYNC_ERROR_CODES = [
  /** A caller's argument is missing, malformed or out of range. */
  'INVALID_ARGUMENT',
  /** A recipient that is not an address of the account's network. */
  'INVALID_ADDRESS',
  /** Text that is not an extended public key, or a key whose path, depth or network disagree. */
  'INVALID_EXTENDED_KEY',
  /** An extended private key: refused, as a watch-only account never needs one. */
  'PRIVATE_KEY_MATERIAL',
  /** A script type, key format or engine feature this version does not have (P2TR, ypub, no public derivation). */
  'UNSUPPORTED',
  /** The key, the adapter and the backend are not all on one network. */
  'NETWORK_MISMATCH',
  /** Not a snapshot this version reads. */
  'INVALID_SNAPSHOT',
  /** A snapshot of another account or network. */
  'SNAPSHOT_MISMATCH',
  /** A payment from an account watched by its address alone: planning one needs its public key. */
  'MISSING_KEY',
  /** A PSBT without the master key's fingerprint, which its signer finds its keys by. */
  'MISSING_FINGERPRINT',
  /** A coin that is not one of the account's, or not one it can spend now. */
  'UNKNOWN_COIN',
  /** The coins cannot pay the amount and the fee. */
  'INSUFFICIENT_FUNDS',
  /** A transaction this account cannot replace: confirmed, not its own, or with descendants. */
  'FEE_BUMP_UNAVAILABLE',
  /** A replacement that would not pay enough more than the transaction it replaces (BIP-125). */
  'FEE_TOO_LOW',
  /** A key derived for a PSBT that is not the key the PSBT names. */
  'KEY_MISMATCH',
  /** The backend could not be reached. */
  'NETWORK_ERROR',
  /** The backend did not answer in time, after every retry. */
  'TIMEOUT',
  /** The caller's `AbortSignal` fired. */
  'ABORTED',
  /** The backend kept answering 429, after every retry. */
  'RATE_LIMITED',
  /** The backend answered with an error status (a 5xx after every retry, or a 4xx). */
  'BACKEND_ERROR',
  /** The backend answered something its API does not document, or that contradicts itself. */
  'INVALID_RESPONSE',
  /** The node refused the transaction; the message carries its reason. */
  'BROADCAST_REJECTED',
] as const

export type SyncErrorCode = (typeof SYNC_ERROR_CODES)[number]

const DEFAULT_MESSAGES: Record<SyncErrorCode, string> = {
  ABORTED: 'The request was aborted.',
  BACKEND_ERROR: 'The backend answered with an error.',
  BROADCAST_REJECTED: 'The node refused the transaction.',
  FEE_BUMP_UNAVAILABLE: 'This transaction cannot be replaced by this account.',
  FEE_TOO_LOW: 'The replacement does not pay enough more than the transaction it replaces.',
  INSUFFICIENT_FUNDS: 'The coins cannot pay the amount and the fee.',
  INVALID_ADDRESS: 'The address is not an address of this network.',
  INVALID_ARGUMENT: 'An argument is missing or out of range.',
  INVALID_EXTENDED_KEY: 'The text is not an extended public key this account can use.',
  INVALID_RESPONSE: 'The backend answered something its API does not document.',
  INVALID_SNAPSHOT: 'The snapshot is not one this version reads.',
  KEY_MISMATCH: 'The derived key is not the one the PSBT names.',
  MISSING_FINGERPRINT: 'A PSBT needs the master key`s fingerprint.',
  MISSING_KEY: 'Payments need the account`s public key; this sync watches an address alone.',
  NETWORK_ERROR: 'The backend could not be reached.',
  NETWORK_MISMATCH: 'The key, the adapter and the backend are not on one network.',
  PRIVATE_KEY_MATERIAL: 'Extended private keys are refused.',
  RATE_LIMITED: 'The backend is rate limiting these requests.',
  SNAPSHOT_MISMATCH: 'The snapshot belongs to another account or network.',
  TIMEOUT: 'The backend did not answer in time.',
  UNKNOWN_COIN: 'The coin is not one this account can spend.',
  UNSUPPORTED: 'This is not supported in this version.',
}

export class SyncError extends Error {
  readonly code: SyncErrorCode

  constructor(code: SyncErrorCode, message: string = DEFAULT_MESSAGES[code], options?: {cause?: unknown}) {
    super(message, options)
    this.name = 'SyncError'
    this.code = code
  }
}

/** Whether `error` is a `SyncError`, of `code` when given; narrows `error.code` to it. */
export const isSyncError = <Code extends SyncErrorCode = SyncErrorCode>(
  error: unknown,
  code?: Code
): error is SyncError & {readonly code: Code} =>
  error instanceof SyncError && (code === undefined || error.code === code)
