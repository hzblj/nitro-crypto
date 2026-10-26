/**
 * Whether 32 bytes decode to a point on the Ed25519 curve: RFC 8032's point decoding (section 5.1.3) over public
 * values only, in BigInt. Program-derived addresses are exactly the digests for which this is false.
 *
 * It decides as the Solana runtime and @solana/kit do: the sign bit is masked off and `y` is reduced modulo p rather
 * than refused when it is not canonical; `x = 0` with the sign bit set is off the curve, as kit decides.
 */

const P = 2n ** 255n - 19n

/** -121665 / 121666 mod p, the curve's `d`. */
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n

/** A square root of -1 mod p: 2^((p - 1) / 4). */
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n

const mod = (value: bigint) => {
  const result = value % P

  return result >= 0n ? result : result + P
}

const power = (base: bigint, exponent: bigint) => {
  let result = 1n
  let square = mod(base)

  for (let rest = exponent; rest > 0n; rest >>= 1n) {
    if (rest & 1n) {
      result = (result * square) % P
    }
    square = (square * square) % P
  }

  return result
}

/** The little-endian integer of 32 bytes, with the top bit (the sign of x) cleared. */
const yOf = (bytes: Uint8Array) => {
  let y = 0n

  for (let index = 31; index >= 0; index--) {
    y = (y << 8n) | BigInt(index === 31 ? (bytes[index] ?? 0) & 0x7f : (bytes[index] ?? 0))
  }

  return y
}

export const isOnCurveBytes = (bytes: Uint8Array): boolean => {
  if (bytes.length !== 32) {
    return false
  }

  const y = mod(yOf(bytes))
  const y2 = mod(y * y)
  const u = mod(y2 - 1n)
  const v = mod(D * y2 + 1n)
  // The candidate root of u / v: u * v^3 * (u * v^7)^((p - 5) / 8).
  const v3 = mod(v * v * v)
  let x = mod(u * v3 * power(u * v3 * v3 * v, (P - 5n) / 8n))
  const vx2 = mod(v * x * x)

  if (vx2 === mod(-u)) {
    x = mod(x * SQRT_M1)
  } else if (vx2 !== u) {
    return false
  }

  return !(x === 0n && ((bytes[31] ?? 0) & 0x80) !== 0)
}
