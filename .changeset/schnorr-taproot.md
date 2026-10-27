---
'@hzblj/nitro-crypto': patch
---

BIP-340 Schnorr signatures and BIP-341 Taproot tweaks, from libsecp256k1's extrakeys and schnorrsig modules. A secp256k1 key gains `xOnlyPublicKey()`, `signSchnorr(message)` (any length, with fresh auxiliary randomness from the OS) and `signTaproot(sighash, merkleRoot?)`, which signs a key path spend with the key tweaked inside the engine (no merkle root: BIP-86). `crypto.schnorr.verify(publicKey, message, signature)` verifies, and `crypto.schnorr.taprootTweak(internalKey, merkleRoot?)` returns the output key and its parity. Adapters declare them as the capabilities `secp256k1-schnorr` and `taproot-tweak`; in the C ABI they are `nc_secp256k1_schnorr_verify`, `nc_secp256k1_taproot_tweak`, `nc_key_public_xonly`, `nc_key_sign_schnorr` and `nc_key_sign_taproot`, and the ABI version stays 1. Held to every BIP-340 vector, BIP-341's wallet vectors and BIP-86's, and to @noble/curves.
