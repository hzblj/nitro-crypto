# Test vectors

Each file is the published vectors of one standard, copied or extracted from that standard's own source, never
computed here. `test/vectors.zig` runs every one of them against the engine.

| File | Source | How it got here |
| --- | --- | --- |
| `bip39.json` | [trezor/python-mnemonic `vectors.json`](https://github.com/trezor/python-mnemonic/blob/master/vectors.json), the vectors BIP-39 links to | The `english` array, reshaped into named fields. Every seed and xprv uses the passphrase `TREZOR`. |
| `bip32.json` | [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), test vectors 1 to 4 | Each chain's `ext prv` decoded from Base58Check (checksum verified) into its parent fingerprint, chain code and key; the xprv and xpub are kept beside them. |
| `slip10.json` | [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), test vectors 1 and 2 for secp256k1 and Ed25519 | Parsed from the document's lists. Ed25519 public keys keep SLIP-0010's `00` prefix. |
| `rfc8032.json` | [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) | Parsed from the RFC's text: TEST 1, 2, 3, 1024 and SHA(abc). |
| `bip340.csv` | [BIP-340 `test-vectors.csv`](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) | Unchanged but for its line endings, CRLF there and LF here (bitcoin/bips at `5aadddb`; the original's SHA-256 is `34c9d1d9…851c2d`). |
| `bip341.json` | [BIP-341 `wallet-test-vectors.json`](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json) | Unchanged (bitcoin/bips at `5aadddb`, SHA-256 `403e19fb…42d37f`). Its key path signatures are made with aux_rand all zero. |
| `wycheproof_ecdsa_secp256k1_sha256_p1363_test.json` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof/tree/main/testvectors_v1) | Unchanged. |
| `wycheproof_ed25519_test.json` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof/tree/main/testvectors_v1) | Unchanged. |

One file is not a standard's but a parity check: `backup.json`, ADR 0009's backup format sealed by an independent
implementation (@noble/hashes' Argon2id and @noble/ciphers' XChaCha20-Poly1305), written by `backup.mjs`
(`node packages/zig-engine-crypto/test/vectors/backup.mjs > packages/zig-engine-crypto/test/vectors/backup.json` at
the root). The engine must seal the same bytes from the same inputs and open them.

Vectors that live in code rather than here: RFC 9106's Argon2id and draft-irtf-cfrg-xchacha's XChaCha20-Poly1305
(`src/backup/backup.zig`), FIPS 180-4 and Keccak digests and RFC 4231 HMACs (`src/hash.zig`), the
RIPEMD-160 reference vectors (`src/ripemd160.zig`), and SEC 2's generator (`src/secp256k1.zig`).

The facade's tests read `bip340.csv` and `bip341.json` from here too, and sign them through the WebAssembly build's
test hook. BIP-86's first receiving key of "abandon ... about" is checked in the C harness and the facade's tests.

The Bitcoin adapter keeps BIP-84's and BIP-350's address vectors in `packages/crypto-bitcoin/test/vectors/`, and the
facade BIP-173's and BIP-350's Bech32 strings in `packages/nitro-crypto/test/vectors/`, extracted the same way.
