let table: Uint32Array | undefined

const crcTable = () => {
  if (!table) {
    table = new Uint32Array(256)

    for (let byte = 0; byte < 256; byte++) {
      let value = byte

      for (let bit = 0; bit < 8; bit++) {
        value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
      }

      table[byte] = value >>> 0
    }
  }

  return table
}

/** CRC-32 as ISO-HDLC, zlib and Bytewords compute it (reflected 0x04c11db7), as an unsigned 32-bit integer. */
export const crc32 = (data: Uint8Array): number => {
  const lookup = crcTable()
  let crc = 0xffffffff

  for (const byte of data) {
    crc = (lookup[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8)
  }

  return (crc ^ 0xffffffff) >>> 0
}
