---
'@hzblj/crypto-bitcoin': patch
---

`decodePsbt` reads a PSBT whose outputs exceed its inputs instead of refusing it, so a wallet can show an unfinished one such as a marketplace offer (a seller's coin and asking price, signed `SIGHASH_SINGLE | ANYONECANPAY`, waiting for a buyer's inputs). The new `balance` is the inputs less the outputs, negative for such a PSBT, whose `fee` is then `undefined`. `signPsbt` and `finalizePsbt` still refuse it: this package signs only `SIGHASH_ALL` (or Taproot's default), which could never complete it.
