/*
 * nitro_crypto.h: the C ABI of the nitro-crypto engine.
 *
 * Chain-agnostic cryptography: random bytes, hashes, HMAC, secp256k1 ECDSA, Ed25519, BIP-39 seeds and
 * hierarchical key derivation (BIP-32 for secp256k1, SLIP-0010 for Ed25519). Nothing here knows about a
 * blockchain; addresses, message formats and networks belong to the adapters above it.
 *
 * Compatibility policy
 *   NC_ABI_VERSION changes whenever a function, a constant or a struct here changes meaning or signature. A
 *   host compiled against one ABI version refuses a library reporting another (nc_abi_version()). Additive
 *   changes (a new function, a new capability bit, a new status code) do not bump it: a host must treat an
 *   unknown status code as NC_ERR_INTERNAL and an unknown capability bit as absent.
 *
 * Memory ownership
 *   The engine never returns memory for the caller to free. Every output is written into a buffer the caller
 *   owns, together with its capacity; a function that writes a variable length reports it through `written`.
 *   Strings returned by nc_engine_version(), nc_status_name() and nc_capability_name() are static.
 *
 *   Secret material (seeds, private keys) stays inside the engine, addressed by an opaque nc_handle. A handle
 *   is released with nc_handle_destroy(), which zeroizes the secret before the slot is reused. Handles carry a
 *   generation, so a destroyed or forged handle is rejected (NC_ERR_INVALID_HANDLE) rather than aliasing a
 *   newer secret. Releasing every handle is the caller's job; the engine holds at most NC_HANDLE_CAPACITY.
 *
 * Threading
 *   Every function may be called from any thread. Handle operations are serialized by the engine.
 *
 * Errors
 *   Every fallible function returns an nc_status: NC_OK (0) or a negative code. Outputs are unspecified after
 *   an error. Status names (nc_status_name) are stable identifiers, never containing input or secret values.
 */
#ifndef NITRO_CRYPTO_H
#define NITRO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_ABI_VERSION 1

/* ------------------------------------------------------------------------------------------------ status */

typedef int32_t nc_status;

#define NC_OK 0
#define NC_ERR_INVALID_ARGUMENT -1      /* a null pointer, an unknown enum value, a zero length where one is required */
#define NC_ERR_BUFFER_TOO_SMALL -2      /* the output capacity is below what the result needs */
#define NC_ERR_INVALID_LENGTH -3        /* an input has a length the algorithm does not accept */
#define NC_ERR_INVALID_PRIVATE_KEY -4   /* zero, or not below the curve order */
#define NC_ERR_INVALID_PUBLIC_KEY -5    /* not a valid encoding of a point on the curve */
#define NC_ERR_INVALID_SIGNATURE -6     /* malformed, out of range, or not canonical (high S) */
#define NC_ERR_VERIFICATION_FAILED -7   /* well-formed, but does not verify */
#define NC_ERR_INVALID_PATH -8          /* a derivation path that does not parse, or a scheme that forbids it */
#define NC_ERR_INVALID_MNEMONIC -9      /* a word count BIP-39 does not define, or a word not in the list */
#define NC_ERR_MNEMONIC_CHECKSUM -10    /* every word is known, but the checksum does not match */
#define NC_ERR_INVALID_HANDLE -11       /* never issued, already destroyed, or of the wrong kind */
#define NC_ERR_HANDLE_LIMIT -12         /* NC_HANDLE_CAPACITY handles are alive */
#define NC_ERR_ENTROPY_UNAVAILABLE -13  /* the operating system did not provide random bytes; nothing was produced */
#define NC_ERR_DERIVATION_FAILED -14    /* BIP-32 produced an invalid child key (probability about 2^-127) */
#define NC_ERR_INTERNAL -15

/** A stable identifier for a status ("NC_ERR_INVALID_LENGTH"), or "NC_ERR_UNKNOWN". Static storage. */
const char *nc_status_name(nc_status status);

/* ---------------------------------------------------------------------------------------- version and caps */

/** The ABI version this library implements. Compare with NC_ABI_VERSION. */
uint32_t nc_abi_version(void);

/** The engine's semantic version, e.g. "0.1.0". Static storage. */
const char *nc_engine_version(void);

/** What the build was made with, for people: "zig 0.16.0, libsecp256k1 0.8.0, ecmult window 8". Static storage. */
const char *nc_build_info(void);

#define NC_CAP_RANDOM (1ull << 0)
#define NC_CAP_SHA256 (1ull << 1)
#define NC_CAP_SHA512 (1ull << 2)
#define NC_CAP_KECCAK256 (1ull << 3)
#define NC_CAP_RIPEMD160 (1ull << 4)
#define NC_CAP_HMAC_SHA256 (1ull << 5)
#define NC_CAP_HMAC_SHA512 (1ull << 6)
#define NC_CAP_SECP256K1_ECDSA (1ull << 7)
#define NC_CAP_SECP256K1_RECOVERY (1ull << 8)
#define NC_CAP_ED25519 (1ull << 9)
#define NC_CAP_BIP39 (1ull << 10)
#define NC_CAP_BIP32_SECP256K1 (1ull << 11)
#define NC_CAP_SLIP10_ED25519 (1ull << 12)

/** Every capability this build provides, as NC_CAP_* bits. */
uint64_t nc_capabilities(void);

/** The stable name of one capability bit index (0 for NC_CAP_RANDOM): "sha256", "secp256k1-ecdsa"... NULL past the last. */
const char *nc_capability_name(uint32_t bit);

/* ------------------------------------------------------------------------------------------------ random */

/** Fills `out` from the operating system's CSPRNG. Fails closed: on NC_ERR_ENTROPY_UNAVAILABLE `out` is zeroed. */
nc_status nc_random_bytes(uint8_t *out, size_t out_len);

/* -------------------------------------------------------------------------------------------------- hash */

#define NC_HASH_SHA256 1
#define NC_HASH_SHA512 2
#define NC_HASH_KECCAK256 3     /* Keccak-256 with the original 0x01 padding, as Ethereum uses; not SHA3-256 */
#define NC_HASH_RIPEMD160 4

/** The digest length of an NC_HASH_* algorithm, or 0 for an unknown one. */
size_t nc_hash_length(uint32_t algorithm);

/** One-shot digest. `out_len` must be at least nc_hash_length(algorithm); `data` may be NULL when `data_len` is 0. */
nc_status nc_hash(uint32_t algorithm, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/** HMAC (RFC 2104) over NC_HASH_SHA256 or NC_HASH_SHA512. */
nc_status nc_hmac(uint32_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                  uint8_t *out, size_t out_len);

/* --------------------------------------------------------------------------------------------- secp256k1 */

#define NC_SECP256K1_PRIVATE_KEY_LENGTH 32
#define NC_SECP256K1_COMPRESSED_LENGTH 33
#define NC_SECP256K1_UNCOMPRESSED_LENGTH 65
#define NC_SECP256K1_DIGEST_LENGTH 32
#define NC_SECP256K1_SIGNATURE_LENGTH 64            /* r || s, big-endian, S in the lower half */
#define NC_SECP256K1_RECOVERABLE_SIGNATURE_LENGTH 65 /* r || s || recovery id (0 to 3) */

/**
 * Re-encodes a SEC1 public key (33 or 65 bytes) compressed (33) or uncompressed (65), validating it.
 * `written` receives the length.
 */
nc_status nc_secp256k1_public_key_convert(const uint8_t *public_key, size_t public_key_len, int32_t compressed,
                                          uint8_t *out, size_t out_len, size_t *written);

/**
 * Verifies a 64-byte compact signature over a 32-byte digest. NC_OK when it verifies,
 * NC_ERR_VERIFICATION_FAILED when it does not, NC_ERR_INVALID_SIGNATURE for a high-S (malleable) signature.
 */
nc_status nc_secp256k1_verify(const uint8_t *public_key, size_t public_key_len, const uint8_t *digest,
                              size_t digest_len, const uint8_t *signature, size_t signature_len);

/** Recovers the public key from a 65-byte recoverable signature over a 32-byte digest. Rejects high S. */
nc_status nc_secp256k1_recover(const uint8_t *digest, size_t digest_len, const uint8_t *signature,
                               size_t signature_len, int32_t compressed, uint8_t *out, size_t out_len,
                               size_t *written);

/* ----------------------------------------------------------------------------------------------- ed25519 */

#define NC_ED25519_SEED_LENGTH 32
#define NC_ED25519_PUBLIC_KEY_LENGTH 32
#define NC_ED25519_SIGNATURE_LENGTH 64

/** RFC 8032 verification, rejecting non-canonical encodings and small-order keys. NC_ERR_VERIFICATION_FAILED otherwise. */
nc_status nc_ed25519_verify(const uint8_t *public_key, size_t public_key_len, const uint8_t *message,
                            size_t message_len, const uint8_t *signature, size_t signature_len);

/* ------------------------------------------------------------------------------------------------ handles */

typedef uint64_t nc_handle; /* 0 is never a valid handle */

#define NC_HANDLE_CAPACITY 1024

#define NC_KIND_SEED 1
#define NC_KIND_SECP256K1_KEY 2
#define NC_KIND_ED25519_KEY 3

/** Zeroizes the secret behind `handle` and releases its slot. NC_ERR_INVALID_HANDLE when it is not alive. */
nc_status nc_handle_destroy(nc_handle handle);

/** The NC_KIND_* of a live handle. */
nc_status nc_handle_kind(nc_handle handle, uint32_t *kind);

/** How many handles are alive: for leak checks and diagnostics. */
uint32_t nc_handle_count(void);

/* ----------------------------------------------------------------------------------------------- mnemonic */

#define NC_SEED_LENGTH 64

/**
 * Checks a BIP-39 English mnemonic: words separated by single ASCII spaces, already NFKD-normalized (which, for
 * the English list, means lowercase ASCII). NC_ERR_INVALID_MNEMONIC or NC_ERR_MNEMONIC_CHECKSUM when it fails.
 */
nc_status nc_mnemonic_validate(const char *mnemonic, size_t mnemonic_len);

/**
 * Generates a fresh mnemonic of `word_count` words (12, 15, 18, 21 or 24) from the OS CSPRNG and stores its
 * BIP-39 seed, under `passphrase` (UTF-8, NFKD-normalized by the caller), as a seed handle. The mnemonic itself
 * is never stored or returned.
 */
nc_status nc_seed_generate(uint32_t word_count, const char *passphrase, size_t passphrase_len, nc_handle *out);

/** Validates `mnemonic` and stores its BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) as a seed handle. */
nc_status nc_seed_from_mnemonic(const char *mnemonic, size_t mnemonic_len, const char *passphrase,
                                size_t passphrase_len, nc_handle *out);

/** The BIP-32 fingerprint of the seed's secp256k1 master key (HASH160 of its public key, first 4 bytes, big-endian). */
nc_status nc_seed_fingerprint(nc_handle seed, uint32_t *out);

/* --------------------------------------------------------------------------------------------- derivation */

#define NC_SCHEME_BIP32_SECP256K1 1 /* BIP-32: hardened and normal steps */
#define NC_SCHEME_SLIP10_ED25519 2  /* SLIP-0010: every step must be hardened */

#define NC_PATH_MAX_DEPTH 32

/**
 * Derives the key at `path` ("m/44'/60'/0'/0/0", hardened steps marked ' or h) from a seed handle and stores it
 * as a key handle of the scheme's curve.
 */
nc_status nc_key_derive(nc_handle seed, uint32_t scheme, const char *path, size_t path_len, nc_handle *out);

/* ------------------------------------------------------------------------------------------------- keys */

#define NC_CURVE_SECP256K1 1
#define NC_CURVE_ED25519 2

/** A fresh key on `curve` from the OS CSPRNG. */
nc_status nc_key_generate(uint32_t curve, nc_handle *out);

/**
 * Stores raw secret material as a key handle: a 32-byte secp256k1 private key, or a 32-byte Ed25519 seed
 * (RFC 8032 secret key). For published test vectors and explicit interoperability only; there is no export.
 */
nc_status nc_key_import(uint32_t curve, const uint8_t *secret, size_t secret_len, nc_handle *out);

/** The public key of a key handle: secp256k1 compressed (33) or uncompressed (65), Ed25519 32 bytes. */
nc_status nc_key_public(nc_handle key, int32_t compressed, uint8_t *out, size_t out_len, size_t *written);

/**
 * Signs with a key handle.
 *   secp256k1: `data` is a 32-byte digest; writes 65 bytes, r || s || recovery id, with RFC 6979 nonces and low S.
 *   Ed25519: `data` is the message (any length); writes the 64-byte RFC 8032 signature.
 */
nc_status nc_key_sign(nc_handle key, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len,
                      size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* NITRO_CRYPTO_H */
