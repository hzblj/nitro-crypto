/*
 * nitro_crypto.h: the C ABI of the nitro-crypto engine.
 *
 * Chain-agnostic cryptography: random bytes, hashes, HMAC, secp256k1 ECDSA, BIP-340 Schnorr signatures and BIP-341
 * key tweaks, Ed25519, BIP-39 seeds and hierarchical key derivation (BIP-32 for secp256k1, SLIP-0010 for Ed25519).
 * Nothing here knows about a blockchain; addresses, message formats and networks belong to the adapters above it.
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
 *   Secret material (seeds, private keys) stays inside the engine, addressed by an opaque nc_handle. The one
 *   secret that comes out is a freshly generated mnemonic (nc_mnemonic_generate), once, for the user to write
 *   down; the caller owns that copy and should zero it when done. A handle
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
#define NC_ERR_DERIVATION_FAILED -14    /* BIP-32 made an invalid child, or BIP-341 an invalid tweak (about 2^-127) */
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
#define NC_CAP_MNEMONIC_GENERATE (1ull << 13)
#define NC_CAP_BIP32_EXTENDED_PUBLIC (1ull << 14)
#define NC_CAP_BIP32_PUBLIC_DERIVATION (1ull << 15)
#define NC_CAP_BIP39_ENTROPY (1ull << 16)
#define NC_CAP_BACKUP_ARGON2ID (1ull << 17)
#define NC_CAP_SECP256K1_SCHNORR (1ull << 18)  /* BIP-340: Schnorr verification, x-only keys, nc_key_sign_schnorr */
#define NC_CAP_TAPROOT_TWEAK (1ull << 19)      /* BIP-341: nc_secp256k1_taproot_tweak, nc_key_sign_taproot */
#define NC_CAP_BACKUP_HKDF_SHA256 (1ull << 20) /* nc_backup_seal_with_key, nc_backup_open_with_key, nc_backup_kdf */

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
#define NC_SECP256K1_XONLY_LENGTH 32                 /* BIP-340's public key: x of the point with even y */
#define NC_SECP256K1_SCHNORR_SIGNATURE_LENGTH 64     /* BIP-340: x(R) || s */
#define NC_TAPROOT_MERKLE_ROOT_LENGTH 32             /* BIP-341: the root of a script tree */

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

/**
 * BIP-340 verification of a 64-byte Schnorr signature over `message`, of any length (NULL when 0), under a 32-byte
 * x-only public key. NC_OK when it verifies; NC_ERR_VERIFICATION_FAILED when it does not, a malformed signature (x(R)
 * not below p, s not below n) included; NC_ERR_INVALID_PUBLIC_KEY when the key is the x coordinate of no point.
 */
nc_status nc_secp256k1_schnorr_verify(const uint8_t *public_key, size_t public_key_len, const uint8_t *message,
                                      size_t message_len, const uint8_t *signature, size_t signature_len);

/**
 * BIP-341's output key Q = P + tG, with t the tagged hash "TapTweak" of x(P) followed by `merkle_root`: the key a P2TR
 * output commits to. `public_key` is the internal key P, x-only (32 bytes) or SEC1 (33 or 65, whose y parity BIP-341
 * drops); `merkle_root` is the root of its script tree (32 bytes), or NULL with length 0 for a key with none (BIP-86).
 * Writes Q compressed, 33 bytes, through `written`: its x coordinate is the 32-byte output key, its prefix (0x02 even,
 * 0x03 odd) the parity a script path's control block carries. Public data only. NC_ERR_DERIVATION_FAILED when t is
 * not below the group order (probability about 2^-128).
 */
nc_status nc_secp256k1_taproot_tweak(const uint8_t *public_key, size_t public_key_len, const uint8_t *merkle_root,
                                     size_t merkle_root_len, uint8_t *out, size_t out_len, size_t *written);

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

/** The longest English mnemonic: 24 words of eight letters and 23 spaces. A buffer this size fits any. */
#define NC_MNEMONIC_MAX_LENGTH 215

/**
 * Generates a fresh mnemonic of `word_count` words (12, 15, 18, 21 or 24) from the OS CSPRNG and writes it into
 * `out`: lowercase ASCII words separated by single spaces, not NUL-terminated, its length through `written`. The
 * engine keeps no copy. `out_len` must fit the longest sentence of that many words (word_count * 9 - 1 bytes),
 * checked before any entropy is drawn, so NC_ERR_BUFFER_TOO_SMALL never depends on the words drawn. This is the
 * one function that hands a secret out: a wallet shows it once for backup, and restores it later through
 * nc_seed_from_mnemonic. The caller should zero `out` when done with it.
 */
nc_status nc_mnemonic_generate(uint32_t word_count, char *out, size_t out_len, size_t *written);

/**
 * Generates a fresh mnemonic of `word_count` words (12, 15, 18, 21 or 24) from the OS CSPRNG and stores its
 * BIP-39 seed, under `passphrase` (UTF-8, NFKD-normalized by the caller), as a seed handle. The mnemonic itself
 * is never stored or returned.
 */
nc_status nc_seed_generate(uint32_t word_count, const char *passphrase, size_t passphrase_len, nc_handle *out);

/** Validates `mnemonic` and stores its BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) as a seed handle. */
nc_status nc_seed_from_mnemonic(const char *mnemonic, size_t mnemonic_len, const char *passphrase,
                                size_t passphrase_len, nc_handle *out);

/** The longest BIP-39 entropy: 32 bytes, behind 24 words. A buffer this size fits any. */
#define NC_ENTROPY_MAX_LENGTH 32

/**
 * Stores the BIP-39 seed of the mnemonic `entropy` encodes (16, 20, 24, 28 or 32 bytes), under `passphrase`, as a
 * seed handle: the seed a wallet restored from those words would have. The mnemonic exists only on this call's
 * stack. For a vault that keeps the entropy, sealed by hardware, rather than the words (ADR 0008); any other
 * NC_ERR_INVALID_LENGTH.
 */
nc_status nc_seed_from_entropy(const uint8_t *entropy, size_t entropy_len, const char *passphrase,
                               size_t passphrase_len, nc_handle *out);

/**
 * The mnemonic `entropy` encodes, into `out` as nc_mnemonic_generate writes one. Like it, a secret handed out, for
 * the one moment a vault shows its words for backup (ADR 0008); the caller should zero `out` when done. `out_len`
 * must fit the longest sentence of that many words, so NC_ERR_BUFFER_TOO_SMALL never depends on the words.
 */
nc_status nc_mnemonic_from_entropy(const uint8_t *entropy, size_t entropy_len, char *out, size_t out_len,
                                   size_t *written);

/**
 * The entropy a mnemonic encodes, after its checksum: what a vault seals when the user restores from words.
 * `out_len` must be at least NC_ENTROPY_MAX_LENGTH; the length is written through `written`. The caller should zero
 * `out` when done. NC_ERR_INVALID_MNEMONIC or NC_ERR_MNEMONIC_CHECKSUM as nc_mnemonic_validate.
 */
nc_status nc_mnemonic_to_entropy(const char *mnemonic, size_t mnemonic_len, uint8_t *out, size_t out_len,
                                 size_t *written);

/* ------------------------------------------------------------------------------------------------- backup */

/** The key derivations a backup names in its sixth byte, after the magic "ncbk" and the version, 1. */
#define NC_BACKUP_KDF_ARGON2ID 1 /* a password, through Argon2id (ADR 0009): nc_backup_seal and nc_backup_open */
#define NC_BACKUP_KDF_KEY 2      /* a 32-byte key, through HKDF-SHA256 (ADR 0010): the _with_key pair */

/** A password-sealed backup's header: magic, version, key derivation, memory, passes, lanes, salt, nonce (ADR 0009). */
#define NC_BACKUP_HEADER_LENGTH 55
/** A key-sealed backup's header: magic, version, key derivation, salt and nonce (ADR 0010). */
#define NC_BACKUP_KEY_HEADER_LENGTH 46
/** The key nc_backup_seal_with_key seals under: 32 bytes, such as a passkey's PRF output. */
#define NC_BACKUP_KEY_LENGTH 32
/**
 * The longest sealed backup of either kind: a password-sealed one's header, 32 bytes of entropy and the 16-byte tag. A
 * buffer this size fits any.
 */
#define NC_BACKUP_MAX_LENGTH (NC_BACKUP_HEADER_LENGTH + 32 + 16)

/**
 * Seals BIP-39 `entropy` (16 to 32 bytes) under `password` (UTF-8, at most 1024 bytes) for a backup that leaves the
 * device: Argon2id over the password with a fresh salt (64 MiB, 3 passes, one lane), then XChaCha20-Poly1305 with a
 * fresh nonce, the header as associated data. Writes the backup, NC_BACKUP_HEADER_LENGTH + entropy_len + 16 bytes,
 * through `written`. The backup is safe to store anywhere: what keeps it is the password. For native callers that
 * hold the entropy, such as a vault (ADR 0009); takes about half a second, so never on a UI thread.
 */
nc_status nc_backup_seal(const uint8_t *entropy, size_t entropy_len, const char *password, size_t password_len,
                         uint8_t *out, size_t out_len, size_t *written);

/**
 * The entropy a backup holds, into `out` (at least NC_ENTROPY_MAX_LENGTH bytes), its length through `written`.
 * NC_ERR_VERIFICATION_FAILED for a wrong password and for any change to the backup alike; NC_ERR_INVALID_ARGUMENT for
 * a header this engine does not read (or parameters out of the bounds it accepts: 19 to 256 MiB, 1 to 10 passes), and
 * for a backup sealed under a key rather than a password (nc_backup_kdf tells them apart).
 * The caller should zero `out` when done.
 */
nc_status nc_backup_open(const uint8_t *backup, size_t backup_len, const char *password, size_t password_len,
                         uint8_t *out, size_t out_len, size_t *written);

/**
 * Seals BIP-39 `entropy` (16 to 32 bytes) under a 32-byte `key` rather than a password: the output of a passkey's PRF
 * extension, or any key as random. HKDF-SHA256 extracts a sealing key from it with a fresh 16-byte salt (no stretching:
 * the key is uniformly random already), then XChaCha20-Poly1305 with a fresh nonce, the header as associated data.
 * Writes the backup, NC_BACKUP_KEY_HEADER_LENGTH + entropy_len + 16 bytes, through `written`. A key of 32 zero bytes,
 * what a buffer nobody filled holds, is NC_ERR_INVALID_ARGUMENT; any other length NC_ERR_INVALID_LENGTH. For native
 * callers that hold the entropy and the key, such as a vault (ADR 0010); quick enough for any thread but JavaScript's,
 * where the key must never be.
 */
nc_status nc_backup_seal_with_key(const uint8_t *entropy, size_t entropy_len, const uint8_t *key, size_t key_len,
                                  uint8_t *out, size_t out_len, size_t *written);

/**
 * The entropy a key-sealed backup holds, into `out` (at least NC_ENTROPY_MAX_LENGTH bytes), its length through
 * `written`. NC_ERR_VERIFICATION_FAILED for a wrong key and for any change to the backup alike; NC_ERR_INVALID_ARGUMENT
 * for a header this engine does not read, and for a backup sealed under a password. The caller should zero `out`.
 */
nc_status nc_backup_open_with_key(const uint8_t *backup, size_t backup_len, const uint8_t *key, size_t key_len,
                                  uint8_t *out, size_t out_len, size_t *written);

/**
 * The key derivation a backup names (NC_BACKUP_KDF_ARGON2ID or NC_BACKUP_KDF_KEY), through `kdf`, without opening it:
 * whether to ask for the password or the passkey. NC_ERR_INVALID_ARGUMENT for a header this engine does not read (a
 * later version, another key derivation, not a backup); NC_ERR_INVALID_LENGTH for a length no backup of that kind has.
 * Says nothing of whether the backup opens.
 */
nc_status nc_backup_kdf(const uint8_t *backup, size_t backup_len, uint32_t *kdf);

/** The BIP-32 fingerprint of the seed's secp256k1 master key (HASH160 of its public key, first 4 bytes, big-endian). */
nc_status nc_seed_fingerprint(nc_handle seed, uint32_t *out);

/**
 * An extended public key as BIP-32 serializes one, without the 4-byte version that names a network and script
 * (xpub, tpub, zpub: the chain's choice): depth (1 byte), parent fingerprint (4, big-endian), child number (4,
 * big-endian), chain code (32), compressed public key (33).
 */
#define NC_EXTENDED_PUBLIC_KEY_LENGTH 74

/**
 * The BIP-32 extended public key at `path` below a seed: what a watch-only wallet derives an account's addresses
 * from, and what a signer shares to pair with one. `path` has at least one step (the master's is refused,
 * NC_ERR_INVALID_PATH); writes NC_EXTENDED_PUBLIC_KEY_LENGTH bytes. No private key leaves: a chain code with a
 * non-hardened child's private key would give the parent's away, and the engine exports no private key (ADR 0007).
 */
nc_status nc_seed_extended_public(nc_handle seed, const char *path, size_t path_len, uint8_t *out, size_t out_len,
                                  size_t *written);

/* --------------------------------------------------------------------------------------------- derivation */

#define NC_SCHEME_BIP32_SECP256K1 1 /* BIP-32: hardened and normal steps */
#define NC_SCHEME_SLIP10_ED25519 2  /* SLIP-0010: every step must be hardened */

#define NC_PATH_MAX_DEPTH 32

/**
 * Derives the key at `path` ("m/44'/60'/0'/0/0", hardened steps marked ' or h) from a seed handle and stores it
 * as a key handle of the scheme's curve.
 */
nc_status nc_key_derive(nc_handle seed, uint32_t scheme, const char *path, size_t path_len, nc_handle *out);

/* ------------------------------------------------------------------------------------- public derivation */

/**
 * BIP-32 public child derivation (CKDpub) from an extended public key of NC_EXTENDED_PUBLIC_KEY_LENGTH bytes, down
 * `path` relative to it ("m/0/5": its sixth receiving key; "m": itself). Every step must be non-hardened
 * (NC_ERR_INVALID_PATH otherwise); a key that is not a point is NC_ERR_INVALID_PUBLIC_KEY, and BIP-32's invalid
 * child NC_ERR_DERIVATION_FAILED. Writes NC_EXTENDED_PUBLIC_KEY_LENGTH bytes. Public data only: no handle, no secret.
 */
nc_status nc_bip32_public_derive(const uint8_t *extended, size_t extended_len, const char *path, size_t path_len,
                                 uint8_t *out, size_t out_len, size_t *written);

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

/** The BIP-340 x-only public key of a secp256k1 key handle: 32 bytes. NC_ERR_INVALID_HANDLE for any other handle. */
nc_status nc_key_public_xonly(nc_handle key, uint8_t *out, size_t out_len, size_t *written);

/**
 * A BIP-340 Schnorr signature by a secp256k1 key handle over `message`, of any length (NULL when 0): 64 bytes. The
 * auxiliary randomness is 32 fresh bytes from the OS CSPRNG, so two signatures of one message differ (both verify);
 * the signature is verified before it is written, as BIP-340's signing ends. NC_ERR_INVALID_HANDLE for any other
 * handle.
 */
nc_status nc_key_sign_schnorr(nc_handle key, const uint8_t *message, size_t message_len, uint8_t *out, size_t out_len,
                              size_t *written);

/**
 * BIP-341's key path: nc_key_sign_schnorr by the key tweaked inside the engine, d + t with t as
 * nc_secp256k1_taproot_tweak computes it from this key's x-only public key and `merkle_root` (d negated first when dG
 * has an odd y). `message` is the 32-byte signature hash (NC_ERR_INVALID_LENGTH otherwise); `merkle_root` is 32 bytes,
 * or NULL with length 0 for a key with no script tree (BIP-86). The signature verifies under the output key
 * nc_secp256k1_taproot_tweak gives for this key's public key; the tweaked key exists only on this call's stack.
 */
nc_status nc_key_sign_taproot(nc_handle key, const uint8_t *message, size_t message_len, const uint8_t *merkle_root,
                              size_t merkle_root_len, uint8_t *out, size_t out_len, size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* NITRO_CRYPTO_H */
