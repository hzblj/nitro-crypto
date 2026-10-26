/**
 * Every failure the package reports, as an `AirgapError` with a stable `code`. A message describes what is wrong and
 * never quotes the input: a scanned string can carry a transaction, a public key or a signature, none of which
 * belongs in a log.
 */

export const AIRGAP_ERROR_CODES = [
  /** Not a UR: the scheme, the type, the sequence, the Bytewords or their checksum. */
  'INVALID_UR',
  /** A well-formed UR of a type the caller did not allow. */
  'UNSUPPORTED_UR_TYPE',
  /** The payload is not CBOR this package reads: malformed, indefinite, nested too deep, or a float. */
  'INVALID_CBOR',
  /** More bytes, parts or items than the configured limits allow. */
  'PAYLOAD_TOO_LARGE',
  /** A multipart part from another message than the parts before it. */
  'SESSION_MISMATCH',
  /** A response that does not answer the request it is checked against. */
  'REQUEST_MISMATCH',
  /** Valid CBOR that breaks its type's schema, or a value the protocol forbids. */
  'INVALID_PROTOCOL_DATA',
  /** A seed, a private key, or a type that carries one: refused, whatever the allowlist says. */
  'PRIVATE_KEY_MATERIAL',
  /** A caller's argument out of range: a fragment length, a limit, an allowlist. */
  'INVALID_ARGUMENT',
] as const

export type AirgapErrorCode = (typeof AIRGAP_ERROR_CODES)[number]

const DEFAULT_MESSAGES: Record<AirgapErrorCode, string> = {
  INVALID_ARGUMENT: 'An argument is missing or out of range.',
  INVALID_CBOR: 'The payload is not valid CBOR.',
  INVALID_PROTOCOL_DATA: 'The payload does not match its type.',
  INVALID_UR: 'The text is not a valid UR.',
  PAYLOAD_TOO_LARGE: 'The payload is larger than the configured limit.',
  PRIVATE_KEY_MATERIAL: 'The payload carries private key material, which is refused.',
  REQUEST_MISMATCH: 'The response does not answer this request.',
  SESSION_MISMATCH: 'This part belongs to another message.',
  UNSUPPORTED_UR_TYPE: 'This UR type is not allowed here.',
}

export class AirgapError extends Error {
  readonly code: AirgapErrorCode

  constructor(code: AirgapErrorCode, message: string = DEFAULT_MESSAGES[code], options?: {cause?: unknown}) {
    super(message, options)
    this.name = 'AirgapError'
    this.code = code
  }
}

/** Whether `error` is an `AirgapError`, of `code` when given; narrows `error.code` to it. */
export const isAirgapError = <Code extends AirgapErrorCode = AirgapErrorCode>(
  error: unknown,
  code?: Code
): error is AirgapError & {readonly code: Code} =>
  error instanceof AirgapError && (code === undefined || error.code === code)
