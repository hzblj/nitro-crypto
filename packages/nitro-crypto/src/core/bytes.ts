/** Moving bytes between the facade's `Uint8Array`s and the engine's `ArrayBuffer`s, without a copy when possible. */

/**
 * The `ArrayBuffer` behind `bytes` when the view covers all of it, else a copy of just the view. Native code reads
 * the buffer whole, so a view onto part of a larger one must not hand over its neighbours.
 */
export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const {buffer, byteLength, byteOffset} = bytes

  if (buffer instanceof ArrayBuffer && byteOffset === 0 && byteLength === buffer.byteLength) {
    return buffer
  }

  return new Uint8Array(bytes).buffer
}

export const fromArrayBuffer = (buffer: ArrayBuffer): Uint8Array<ArrayBuffer> => new Uint8Array(buffer)

export const concatBytes = (...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0

  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }

  return out
}

/** Equality without an early exit, so comparing a secret does not tell how much of it matched. */
export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false
  }

  let difference = 0

  for (let index = 0; index < a.length; index++) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0)
  }

  return difference === 0
}

/** Overwrites a buffer that held a secret. Best effort: the runtime may already have copied it. */
export const wipe = (bytes: Uint8Array): void => {
  bytes.fill(0)
}

export const isBytes = (value: unknown): value is Uint8Array => value instanceof Uint8Array
