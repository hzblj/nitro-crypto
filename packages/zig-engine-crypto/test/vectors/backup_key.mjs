// Key-sealed backup vectors from an independent implementation: @noble/hashes' HKDF-SHA256 and @noble/ciphers'
// XChaCha20-Poly1305, composed as ADR 0010's format says.
import {xchacha20poly1305} from '@noble/ciphers/chacha.js'
import {hkdf} from '@noble/hashes/hkdf.js'
import {sha256} from '@noble/hashes/sha2.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

const header = (salt, nonce) => {
  const out = new Uint8Array(46)
  out.set(utf8ToBytes('ncbk'), 0)
  out[4] = 1
  out[5] = 2
  out.set(salt, 6)
  out.set(nonce, 22)
  return out
}

const cases = [
  {entropy: '00000000000000000000000000000000', key: '0101010101010101010101010101010101010101010101010101010101010101'},
  {entropy: '808080808080808080808080808080808080808080808080', key: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'},
  {
    entropy: '8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a190',
    key: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
  },
]

const vectors = cases.map(({entropy, key}, index) => {
  const salt = Uint8Array.from({length: 16}, (_, i) => (i * 11 + index) & 0xff)
  const nonce = Uint8Array.from({length: 24}, (_, i) => (0x80 + i * 5 + index) & 0xff)
  const head = header(salt, nonce)
  const sealingKey = hkdf(sha256, hexToBytes(key), salt, utf8ToBytes('ncbk xchacha20poly1305 key'), 32)
  const sealed = xchacha20poly1305(sealingKey, nonce, head).encrypt(hexToBytes(entropy))
  const backup = new Uint8Array(head.length + sealed.length)
  backup.set(head)
  backup.set(sealed, head.length)
  return {backup: bytesToHex(backup), entropy, key, nonce: bytesToHex(nonce), salt: bytesToHex(salt)}
})

console.log(
  JSON.stringify(
    {source: '@noble/hashes 2.x hkdf and sha256 and @noble/ciphers 1.3 xchacha20poly1305, composed as docs/adr/0010 says', vectors},
    null,
    2
  )
)
