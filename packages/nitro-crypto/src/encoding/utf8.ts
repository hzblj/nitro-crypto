/**
 * UTF-8 without `TextEncoder`/`TextDecoder`, which not every React Native runtime has. Lone surrogates encode as
 * U+FFFD, and malformed input decodes to U+FFFD, as the WHATWG encoders do.
 */

const REPLACEMENT = 0xfffd

const codePoints = function* (text: string): Generator<number> {
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index)

    if (unit >= 0xd800 && unit <= 0xdbff && index + 1 < text.length) {
      const next = text.charCodeAt(index + 1)

      if (next >= 0xdc00 && next <= 0xdfff) {
        index++
        yield 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00)
        continue
      }
    }

    yield unit >= 0xd800 && unit <= 0xdfff ? REPLACEMENT : unit
  }
}

const encode = (text: string): Uint8Array<ArrayBuffer> => {
  const out: number[] = []

  for (const point of codePoints(text)) {
    if (point < 0x80) {
      out.push(point)
    } else if (point < 0x800) {
      out.push(0xc0 | (point >> 6), 0x80 | (point & 63))
    } else if (point < 0x10000) {
      out.push(0xe0 | (point >> 12), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63))
    } else {
      out.push(0xf0 | (point >> 18), 0x80 | ((point >> 12) & 63), 0x80 | ((point >> 6) & 63), 0x80 | (point & 63))
    }
  }

  return Uint8Array.from(out)
}

/** The WHATWG UTF-8 decoder: each maximal invalid subsequence becomes one U+FFFD, exactly as `TextDecoder` does. */
const decode = (bytes: Uint8Array): string => {
  let out = ''
  let needed = 0
  let seen = 0
  let point = 0
  let lower = 0x80
  let upper = 0xbf

  for (let index = 0; index < bytes.length; index++) {
    const byte = bytes[index] ?? 0

    if (needed === 0) {
      if (byte <= 0x7f) {
        out += String.fromCharCode(byte)
      } else if (byte >= 0xc2 && byte <= 0xdf) {
        needed = 1
        point = byte & 0x1f
      } else if (byte >= 0xe0 && byte <= 0xef) {
        lower = byte === 0xe0 ? 0xa0 : 0x80
        upper = byte === 0xed ? 0x9f : 0xbf
        needed = 2
        point = byte & 0xf
      } else if (byte >= 0xf0 && byte <= 0xf4) {
        lower = byte === 0xf0 ? 0x90 : 0x80
        upper = byte === 0xf4 ? 0x8f : 0xbf
        needed = 3
        point = byte & 0x7
      } else {
        out += String.fromCodePoint(REPLACEMENT)
      }

      continue
    }

    if (byte < lower || byte > upper) {
      needed = 0
      seen = 0
      lower = 0x80
      upper = 0xbf
      out += String.fromCodePoint(REPLACEMENT)
      index--
      continue
    }

    lower = 0x80
    upper = 0xbf
    point = (point << 6) | (byte & 0x3f)
    seen++

    if (seen === needed) {
      out += String.fromCodePoint(point)
      needed = 0
      seen = 0
    }
  }

  return needed === 0 ? out : out + String.fromCodePoint(REPLACEMENT)
}

export const utf8 = {decode, encode}
