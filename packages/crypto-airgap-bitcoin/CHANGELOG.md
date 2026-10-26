# @hzblj/crypto-airgap-bitcoin

## 0.1.0

### Minor Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`728e943`](https://github.com/hzblj/nitro-crypto/commit/728e9437dd4575d3d9a6d0518fd9b23c49458920) Thanks [@hzblj](https://github.com/hzblj)! - Air-gapped signing as data, in four new packages. `@hzblj/crypto-airgap` is the payload protocol and nothing around it: Uniform Resources (BC-UR v2) with Bytewords, deterministic CBOR and fountain-coded multipart parts (`createMultipartEncoder`, `createMultipartDecoder`: strings in and out, no QR, camera or timer), a typed registry, and the public account types (`crypto-hdkey`, `crypto-keypath`, `crypto-coin-info`, `crypto-eckey`, `crypto-multi-accounts`). Every decoder takes an allowlist, bounds sizes and parts, refuses seeds and private keys whatever the allowlist says, and reports stable `AirgapError` codes that never quote the input. Parts are byte for byte those of Blockchain Commons' reference implementation and `@ngraveio/bc-ur`. The chain packages bind to a chain client and check every answer against its question: `@hzblj/crypto-airgap-bitcoin` carries PSBTs as `crypto-psbt` and accounts as `crypto-account`, `@hzblj/crypto-airgap-ethereum` speaks ERC-4527 (`eth-sign-request`, `eth-signature`) for EIP-1559 transactions and personal messages, and `@hzblj/crypto-airgap-solana` Keystone's `sol-sign-request` and `sol-signature` for legacy transactions and messages. Their CBOR is byte for byte Keystone's registries'. Accounts pair as extended public keys, as Sparrow (`crypto-account`) and MetaMask's QR hardware wallets (`crypto-hdkey`, children `0/*`, the note `account.standard`) read them (`accountKey`); `watchAccount` watches any address of an account key a hardware wallet shares; a signer reads requests for any address of its account (`{fingerprint, accountPath}`) and signs them with `signRequest`, each key derived at its path and checked against the request. Tested against Keystone's firmware codec (`keystone-sdk-rust`), Keystone's and OneKey's own payloads, `@scure/bip32` and viem.

### Patch Changes

- [#4](https://github.com/hzblj/nitro-crypto/pull/4) [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba) Thanks [@hzblj](https://github.com/hzblj)! - The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.

- Updated dependencies [[`728e943`](https://github.com/hzblj/nitro-crypto/commit/728e9437dd4575d3d9a6d0518fd9b23c49458920), [`219ccf7`](https://github.com/hzblj/nitro-crypto/commit/219ccf7ef493c3a89854d4fdc500568e578cfabc), [`185dac9`](https://github.com/hzblj/nitro-crypto/commit/185dac9c5f27a932e0ad0160fb8cb2c31efdd0b3), [`65f53ca`](https://github.com/hzblj/nitro-crypto/commit/65f53ca5723969fea2d7f6184b52217831da58ba)]:
  - @hzblj/crypto-airgap@0.1.0
  - @hzblj/crypto-bitcoin@0.2.0
  - @hzblj/nitro-crypto@0.1.2
