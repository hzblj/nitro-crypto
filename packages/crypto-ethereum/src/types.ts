export type Keccak256 = (data: Uint8Array) => Uint8Array

/** A `0x`-prefixed hex string. */
export type Hex = `0x${string}`

/** What `signMessage` and `verifyMessage` take: text (signed as its UTF-8 bytes) or raw bytes. */
export type SignableMessage = string | Uint8Array
