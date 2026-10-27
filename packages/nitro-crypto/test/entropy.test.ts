import assert from 'node:assert/strict'
import {test} from 'node:test'

import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'

import {utf8} from '../src/encoding'
import {createAbi} from './abi'
import {ABANDON, crypto} from './support'

/**
 * Seeds from BIP-39 entropy under a passphrase, as a vault makes them through `interop::seedFromEntropy` (ADR 0008):
 * the C ABI through the WebAssembly build, since no JavaScript API takes entropy.
 */
const abi = createAbi()

const fingerprintFromEntropy = (entropy: Uint8Array, passphrase: Uint8Array): string =>
  abi.frame(frame => {
    const handle = frame.allocate(8)
    const status = abi.engine.nc_seed_from_entropy(...frame.input(entropy), ...frame.input(passphrase), handle)
    assert.equal(abi.statusName(status), 'NC_OK')
    const seed = frame.u64(handle)
    const fingerprint = frame.allocate(4)
    assert.equal(abi.engine.nc_seed_fingerprint(seed, fingerprint), 0)
    assert.equal(abi.engine.nc_handle_destroy(seed), 0)

    return frame.u32(fingerprint).toString(16).padStart(8, '0')
  })

test('a passphrase NFKD-normalized by the caller makes the seed the facade and @scure make; NFC does not', async () => {
  const entropy = new Uint8Array(16)

  for (const passphrase of ['', 'TREZOR', 'ñandú 日本', 'Ｃｒｙｐｔｏ ﬁ ①']) {
    const nfkd = passphrase.normalize('NFKD')
    const scure = HDKey.fromMasterSeed(mnemonicToSeedSync(ABANDON, passphrase))
      .fingerprint.toString(16)
      .padStart(8, '0')
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase})
    const facade = wallet.fingerprint.toString(16).padStart(8, '0')
    wallet.dispose()

    assert.equal(fingerprintFromEntropy(entropy, utf8.encode(nfkd)), scure, passphrase)
    assert.equal(facade, scure, passphrase)

    if (passphrase.normalize('NFC') !== nfkd) {
      // The engine hashes the bytes it is given: a native caller that skips NFKD makes another wallet.
      assert.notEqual(fingerprintFromEntropy(entropy, utf8.encode(passphrase.normalize('NFC'))), scure, passphrase)
    }
  }

  const tooLong = new Uint8Array(1025).fill(0x61)
  abi.frame(frame => {
    const status = abi.engine.nc_seed_from_entropy(...frame.input(entropy), ...frame.input(tooLong), frame.allocate(8))
    assert.equal(abi.statusName(status), 'NC_ERR_INVALID_LENGTH')
  })
  assert.equal(abi.engine.nc_handle_count(), 0)
})
