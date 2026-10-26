// Backup vectors from an independent implementation: @noble/hashes' Argon2id and @noble/ciphers' XChaCha20-Poly1305,
// composed as ADR 0009's format says.
import {xchacha20poly1305} from '@noble/ciphers/chacha.js'
import {argon2id} from '@noble/hashes/argon2.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'

const header = (m, t, salt, nonce) => {
  const out = new Uint8Array(55)
  out.set(utf8ToBytes('ncbk'), 0)
  out[4] = 1
  out[5] = 1
  new DataView(out.buffer).setUint32(6, m)
  new DataView(out.buffer).setUint32(10, t)
  out[14] = 1
  out.set(salt, 15)
  out.set(nonce, 31)
  return out
}

const cases = [
  {entropy: '00000000000000000000000000000000', m: 256, password: 'correct horse battery staple', t: 2},
  {entropy: '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', m: 512, password: 'ñandú 日本 🦊', t: 3},
  {entropy: '0c1e24e5917779d297e14d45f14e1a1a', m: 1024, password: '', t: 1},
]

const vectors = cases.map(({entropy, m, password, t}, index) => {
  const salt = Uint8Array.from({length: 16}, (_, i) => (i * 7 + index) & 0xff)
  const nonce = Uint8Array.from({length: 24}, (_, i) => (0x40 + i * 3 + index) & 0xff)
  const head = header(m, t, salt, nonce)
  const key = argon2id(utf8ToBytes(password), salt, {dkLen: 32, m, p: 1, t})
  const sealed = xchacha20poly1305(key, nonce, head).encrypt(hexToBytes(entropy))
  const backup = new Uint8Array(head.length + sealed.length)
  backup.set(head)
  backup.set(sealed, head.length)
  return {backup: bytesToHex(backup), entropy, memory: m, nonce: bytesToHex(nonce), passes: t, password, salt: bytesToHex(salt)}
})

console.log(JSON.stringify({source: '@noble/hashes 2.x argon2id and @noble/ciphers 1.3 xchacha20poly1305, composed as docs/adr/0009 says', vectors}, null, 2))
