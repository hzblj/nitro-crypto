import type {UR} from './ur'

/**
 * The two sides of air-gapped signing for one chain. A watch-only wallet, online, encodes what it wants signed and
 * checks the answer against what it asked (`AirgapRequester`); a signer, offline, reads a request and encodes its
 * signature (`AirgapResponder`). Each chain package implements both with its own types, on its own UR types, and
 * the UR codec knows none of them: a new chain adds a package and changes nothing here.
 */
export type AirgapRequester<Request, Response, ResponseContext> = {
  /** The chain, as its package names it: `bitcoin`, `ethereum`, `solana`. */
  readonly chain: string
  /** The UR types a request travels as. */
  readonly requestTypes: readonly string[]
  /** The UR types a response travels as: a decoder's `allowedTypes` when scanning one. */
  readonly responseTypes: readonly string[]
  readonly encodeSignRequest: (request: Request) => UR
  /**
   * The response, checked against the request it answers (`context`): its id, its signer, what it signs. A
   * response that answers another request is `REQUEST_MISMATCH`, whatever else is right about it.
   */
  readonly decodeSignResponse: (ur: UR, context: ResponseContext) => Response
}

export type AirgapResponder<SignRequest, SignRequestContext, Signature> = {
  readonly chain: string
  readonly requestTypes: readonly string[]
  readonly responseTypes: readonly string[]
  /**
   * The request, read and checked for this signer (`context`: its fingerprint, its accounts). Decoding is not
   * consent: the signer shows what the request does and asks before it signs anything.
   */
  readonly decodeSignRequest: (ur: UR, context: SignRequestContext) => SignRequest
  readonly encodeSignResponse: (signature: Signature) => UR
}
