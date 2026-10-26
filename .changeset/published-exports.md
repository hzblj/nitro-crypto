---
'@hzblj/nitro-crypto': patch
'@hzblj/crypto-bitcoin': patch
'@hzblj/crypto-ethereum': patch
'@hzblj/crypto-solana': patch
'@hzblj/crypto-airgap': patch
'@hzblj/crypto-airgap-bitcoin': patch
'@hzblj/crypto-airgap-ethereum': patch
'@hzblj/crypto-airgap-solana': patch
---

The published `exports` no longer name a `source` condition. It pointed at `src/`, which the package does not ship, so a project that resolves with that condition (a monorepo's own tests often do) found nothing; the published map now has only `types` and `default`.
