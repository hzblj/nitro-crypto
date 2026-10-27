/*
 * The C ABI as a C host sees it: include/nitro_crypto.h and the static library, nothing from Zig. Covers what
 * the Zig unit tests cannot: the exported symbols and their calling convention, argument checking at the
 * boundary, handle ownership across calls, large payloads, repetition without leaks, and threads.
 */
#include "nitro_crypto.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition);   \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

#define CHECK_STATUS(expected, call)                                                        \
    do {                                                                                    \
        nc_status status_ = (call);                                                         \
        if (status_ != (expected)) {                                                        \
            fprintf(stderr, "%s:%d: %s returned %s, expected %s\n", __FILE__, __LINE__, #call, \
                    nc_status_name(status_), nc_status_name(expected));                     \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

static void hex_decode(const char *hex, uint8_t *out, size_t length) {
    for (size_t i = 0; i < length; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static int equals_hex(const uint8_t *bytes, const char *hex) {
    size_t length = strlen(hex) / 2;
    uint8_t expected[128];
    hex_decode(hex, expected, length);
    return memcmp(bytes, expected, length) == 0;
}

static const char *ABANDON =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/* ------------------------------------------------------------------------------------- version, statuses */

static void test_version_and_capabilities(void) {
    CHECK(nc_abi_version() == NC_ABI_VERSION);
    CHECK(strlen(nc_engine_version()) >= 5);
    CHECK(strncmp(nc_build_info(), "zig ", 4) == 0);

    uint64_t caps = nc_capabilities();
    CHECK((caps & NC_CAP_RANDOM) && (caps & NC_CAP_KECCAK256) && (caps & NC_CAP_SECP256K1_RECOVERY));
    CHECK((caps & NC_CAP_BIP39) && (caps & NC_CAP_BIP32_SECP256K1) && (caps & NC_CAP_SLIP10_ED25519));
    for (uint32_t bit = 0; bit < 64; bit++) {
        int has = (caps >> bit) & 1;
        CHECK(has == (nc_capability_name(bit) != NULL));
    }
    CHECK(strcmp(nc_capability_name(3), "keccak256") == 0);
    CHECK(strcmp(nc_capability_name(12), "slip10-ed25519") == 0);
    CHECK((caps & NC_CAP_MNEMONIC_GENERATE) && strcmp(nc_capability_name(13), "mnemonic-generate") == 0);
    CHECK((caps & NC_CAP_BIP32_EXTENDED_PUBLIC) && strcmp(nc_capability_name(14), "bip32-extended-public") == 0);
    CHECK((caps & NC_CAP_BIP32_PUBLIC_DERIVATION) && strcmp(nc_capability_name(15), "bip32-public-derivation") == 0);
    CHECK((caps & NC_CAP_BIP39_ENTROPY) && strcmp(nc_capability_name(16), "bip39-entropy") == 0);
    CHECK((caps & NC_CAP_BACKUP_ARGON2ID) && strcmp(nc_capability_name(17), "backup-argon2id") == 0);
    CHECK((caps & NC_CAP_SECP256K1_SCHNORR) && strcmp(nc_capability_name(18), "secp256k1-schnorr") == 0);
    CHECK((caps & NC_CAP_TAPROOT_TWEAK) && strcmp(nc_capability_name(19), "taproot-tweak") == 0);
    CHECK((caps & NC_CAP_BACKUP_HKDF_SHA256) && strcmp(nc_capability_name(20), "backup-hkdf-sha256") == 0);
}

static void test_status_names(void) {
    CHECK(strcmp(nc_status_name(NC_OK), "NC_OK") == 0);
    CHECK(strcmp(nc_status_name(NC_ERR_INVALID_LENGTH), "NC_ERR_INVALID_LENGTH") == 0);
    CHECK(strcmp(nc_status_name(NC_ERR_INTERNAL), "NC_ERR_INTERNAL") == 0);
    CHECK(strcmp(nc_status_name(12345), "NC_ERR_UNKNOWN") == 0);
}

/* ------------------------------------------------------------------------------------ random and hashes */

static void test_random(void) {
    CHECK_STATUS(NC_OK, nc_random_bytes(NULL, 0));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_random_bytes(NULL, 1));

    size_t length = 1 << 20;
    uint8_t *a = calloc(length, 1), *b = calloc(length, 1);
    CHECK_STATUS(NC_OK, nc_random_bytes(a, length));
    CHECK_STATUS(NC_OK, nc_random_bytes(b, length));
    CHECK(memcmp(a, b, length) != 0);
    free(a);
    free(b);
}

static void test_hash(void) {
    uint8_t out[64];
    CHECK(nc_hash_length(NC_HASH_SHA256) == 32 && nc_hash_length(NC_HASH_SHA512) == 64);
    CHECK(nc_hash_length(NC_HASH_KECCAK256) == 32 && nc_hash_length(NC_HASH_RIPEMD160) == 20);
    CHECK(nc_hash_length(0) == 0 && nc_hash_length(99) == 0);

    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_SHA256, (const uint8_t *)"abc", 3, out, sizeof out));
    CHECK(equals_hex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_KECCAK256, NULL, 0, out, 32));
    CHECK(equals_hex(out, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_RIPEMD160, (const uint8_t *)"abc", 3, out, 20));
    CHECK(equals_hex(out, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));

    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_hash(0, (const uint8_t *)"abc", 3, out, sizeof out));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_hash(NC_HASH_SHA256, NULL, 3, out, sizeof out));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_hash(NC_HASH_SHA256, (const uint8_t *)"abc", 3, NULL, 32));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_hash(NC_HASH_SHA256, (const uint8_t *)"abc", 3, out, 31));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_hash(NC_HASH_SHA512, (const uint8_t *)"abc", 3, out, 32));
}

static void test_large_payload(void) {
    /* 64 MiB, hashed whole: the boundary takes any length a host can hold. */
    size_t length = 64u << 20;
    uint8_t *data = malloc(length);
    memset(data, 'a', length);
    uint8_t first[32], second[32];
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_SHA256, data, length, first, 32));
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_SHA256, data, length, second, 32));
    CHECK(memcmp(first, second, 32) == 0);
    data[length - 1] = 'b';
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_SHA256, data, length, second, 32));
    CHECK(memcmp(first, second, 32) != 0);
    free(data);
}

static void test_hmac(void) {
    uint8_t out[64];
    /* RFC 4231 test case 2. */
    const char *data = "what do ya want for nothing?";
    CHECK_STATUS(NC_OK, nc_hmac(NC_HASH_SHA512, (const uint8_t *)"Jefe", 4, (const uint8_t *)data, strlen(data), out, 64));
    CHECK(equals_hex(out, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_hmac(NC_HASH_KECCAK256, (const uint8_t *)"k", 1, NULL, 0, out, 64));
}

/* ------------------------------------------------------------------------------------- curves, stateless */

static void test_secp256k1_public(void) {
    uint8_t generator[33], out[65];
    size_t written = 0;
    hex_decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", generator, 33);
    CHECK_STATUS(NC_OK, nc_secp256k1_public_key_convert(generator, 33, 0, out, 65, &written));
    CHECK(written == 65 && out[0] == 0x04);
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_public_key_convert(generator, 32, 0, out, 65, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_secp256k1_public_key_convert(generator, 33, 0, out, 64, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_secp256k1_public_key_convert(generator, 33, 0, out, 65, NULL));
    generator[0] = 0x05;
    CHECK_STATUS(NC_ERR_INVALID_PUBLIC_KEY, nc_secp256k1_public_key_convert(generator, 33, 1, out, 65, &written));
}

static void test_ed25519_verify(void) {
    /* RFC 8032 section 7.1, TEST 1 (the empty message). */
    uint8_t public_key[32], signature[64];
    hex_decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", public_key, 32);
    hex_decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", signature, 64);
    CHECK_STATUS(NC_OK, nc_ed25519_verify(public_key, 32, NULL, 0, signature, 64));
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_ed25519_verify(public_key, 32, (const uint8_t *)"x", 1, signature, 64));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_ed25519_verify(public_key, 31, NULL, 0, signature, 64));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_ed25519_verify(public_key, 32, NULL, 0, signature, 63));
}

/* BIP-340 vector 1 (verify only, from its public parts), and BIP-341's first two scriptPubKey vectors. */
static void test_schnorr_public(void) {
    uint8_t public_key[32], message[32], signature[64], out[33];
    size_t written = 0;
    hex_decode("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", public_key, 32);
    hex_decode("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", message, 32);
    hex_decode("6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a", signature, 64);
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(public_key, 32, message, 32, signature, 64));
    message[31] ^= 1;
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_secp256k1_schnorr_verify(public_key, 32, message, 32, signature, 64));
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_secp256k1_schnorr_verify(public_key, 32, NULL, 0, signature, 64));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_schnorr_verify(public_key, 33, message, 32, signature, 64));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_schnorr_verify(public_key, 32, message, 32, signature, 65));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_secp256k1_schnorr_verify(public_key, 32, NULL, 32, signature, 64));
    /* BIP-340 vector 14: a public key above the field size. */
    memset(public_key, 0xff, 32);
    CHECK_STATUS(NC_ERR_INVALID_PUBLIC_KEY, nc_secp256k1_schnorr_verify(public_key, 32, message, 32, signature, 64));

    /* No script tree: Q's x and its parity (BIP-341 wallet vector 0); then one with a merkle root (vector 1). */
    uint8_t merkle_root[32];
    hex_decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", public_key, 32);
    CHECK_STATUS(NC_OK, nc_secp256k1_taproot_tweak(public_key, 32, NULL, 0, out, 33, &written));
    CHECK(written == 33 && equals_hex(out + 1, "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"));
    hex_decode("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", public_key, 32);
    hex_decode("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", merkle_root, 32);
    CHECK_STATUS(NC_OK, nc_secp256k1_taproot_tweak(public_key, 32, merkle_root, 32, out, 33, &written));
    CHECK(out[0] == 0x03 && equals_hex(out + 1, "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_taproot_tweak(public_key, 32, merkle_root, 31, out, 33, &written));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_taproot_tweak(public_key, 31, NULL, 0, out, 33, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_secp256k1_taproot_tweak(public_key, 32, NULL, 32, out, 33, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_secp256k1_taproot_tweak(public_key, 32, NULL, 0, out, 32, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_secp256k1_taproot_tweak(public_key, 32, NULL, 0, out, 33, NULL));
}

/* ------------------------------------------------------------------------------------------ seeds, keys */

static void test_mnemonic(void) {
    CHECK_STATUS(NC_OK, nc_mnemonic_validate(ABANDON, strlen(ABANDON)));
    const char *checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    CHECK_STATUS(NC_ERR_MNEMONIC_CHECKSUM, nc_mnemonic_validate(checksum, strlen(checksum)));
    const char *unknown = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy";
    CHECK_STATUS(NC_ERR_INVALID_MNEMONIC, nc_mnemonic_validate(unknown, strlen(unknown)));
    CHECK_STATUS(NC_ERR_INVALID_MNEMONIC, nc_mnemonic_validate(NULL, 0));
}

static size_t count_words(const char *sentence, size_t length) {
    size_t words = length > 0 ? 1 : 0;
    for (size_t i = 0; i < length; i++) words += sentence[i] == ' ';
    return words;
}

_Static_assert(NC_MNEMONIC_MAX_LENGTH == 24 * 9 - 1, "the longest mnemonic: 24 eight-letter words, 23 spaces");

static void test_mnemonic_generate(void) {
    uint32_t baseline = nc_handle_count();
    char out[NC_MNEMONIC_MAX_LENGTH], other[NC_MNEMONIC_MAX_LENGTH];
    size_t written = 0, other_written = 0;
    static const uint32_t counts[] = {12, 15, 18, 21, 24};

    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        CHECK_STATUS(NC_OK, nc_mnemonic_generate(counts[i], out, sizeof out, &written));
        CHECK(count_words(out, written) == counts[i]);
        CHECK_STATUS(NC_OK, nc_mnemonic_validate(out, written));

        /* What it generates seeds a wallet like any mnemonic. */
        nc_handle seed = 0;
        CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(out, written, NULL, 0, &seed));
        CHECK_STATUS(NC_OK, nc_handle_destroy(seed));
    }

    CHECK_STATUS(NC_OK, nc_mnemonic_generate(12, out, 12 * 9 - 1, &written));
    CHECK_STATUS(NC_OK, nc_mnemonic_generate(12, other, sizeof other, &other_written));
    CHECK(written != other_written || memcmp(out, other, written) != 0);

    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_mnemonic_generate(12, out, 12 * 9 - 2, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_mnemonic_generate(13, out, sizeof out, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_mnemonic_generate(12, NULL, sizeof out, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_mnemonic_generate(12, out, sizeof out, NULL));
    CHECK(nc_handle_count() == baseline);
    memset(out, 0, sizeof out);
    memset(other, 0, sizeof other);
}

/* Entropy to words and back, and to the seed those words make: what a vault that keeps entropy relies on. */
static void test_entropy(void) {
    uint32_t baseline = nc_handle_count();
    static const uint8_t zero[16] = {0};
    char words[NC_MNEMONIC_MAX_LENGTH];
    uint8_t entropy[NC_ENTROPY_MAX_LENGTH];
    size_t written = 0;

    CHECK_STATUS(NC_OK, nc_mnemonic_from_entropy(zero, sizeof zero, words, 12 * 9 - 1, &written));
    CHECK(written == strlen(ABANDON) && memcmp(words, ABANDON, written) == 0);
    CHECK_STATUS(NC_OK, nc_mnemonic_to_entropy(ABANDON, strlen(ABANDON), entropy, sizeof entropy, &written));
    CHECK(written == 16 && memcmp(entropy, zero, 16) == 0);

    /* The same seed as the words make, under the same passphrase. */
    nc_handle from_words = 0, from_entropy = 0;
    uint32_t a = 0, b = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), "TREZOR", 6, &from_words));
    CHECK_STATUS(NC_OK, nc_seed_from_entropy(zero, sizeof zero, "TREZOR", 6, &from_entropy));
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(from_words, &a));
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(from_entropy, &b));
    CHECK(a == b);
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_words));
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_entropy));

    /* A passphrase is hashed as given, so the caller normalizes it: e-acute in NFKD (e, then U+0301) makes the seed the
       words make under it, NFC (U+00E9) another. */
    const char *nfkd = "e\xcc\x81", *nfc = "\xc3\xa9";
    nc_handle from_nfc = 0;
    uint32_t c = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), nfkd, strlen(nfkd), &from_words));
    CHECK_STATUS(NC_OK, nc_seed_from_entropy(zero, sizeof zero, nfkd, strlen(nfkd), &from_entropy));
    CHECK_STATUS(NC_OK, nc_seed_from_entropy(zero, sizeof zero, nfc, strlen(nfc), &from_nfc));
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(from_words, &a));
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(from_entropy, &b));
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(from_nfc, &c));
    CHECK(a == b && b != c);
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_words));
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_entropy));
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_nfc));
    static char long_passphrase[1025];
    memset(long_passphrase, 'a', sizeof long_passphrase);
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_seed_from_entropy(zero, 16, long_passphrase, 1025, &from_entropy));
    CHECK_STATUS(NC_OK, nc_seed_from_entropy(zero, 16, long_passphrase, 1024, &from_entropy));
    CHECK_STATUS(NC_OK, nc_handle_destroy(from_entropy));

    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_seed_from_entropy(zero, 15, NULL, 0, &from_entropy));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_mnemonic_from_entropy(zero, 15, words, sizeof words, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_mnemonic_from_entropy(zero, 16, words, 12 * 9 - 2, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_mnemonic_to_entropy(ABANDON, strlen(ABANDON), entropy, 31, &written));
    const char *bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    CHECK_STATUS(NC_ERR_MNEMONIC_CHECKSUM, nc_mnemonic_to_entropy(bad, strlen(bad), entropy, sizeof entropy, &written));
    CHECK(nc_handle_count() == baseline);
    memset(words, 0, sizeof words);
    memset(entropy, 0, sizeof entropy);
}

/* A backup with the real parameters (64 MiB, 3 passes): sealed, opened, and refused with another password. */
static void test_backup(void) {
    static const uint8_t entropy[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    const char *password = "correct horse battery staple";
    uint8_t sealed[NC_BACKUP_MAX_LENGTH], other[NC_BACKUP_MAX_LENGTH], opened[NC_ENTROPY_MAX_LENGTH];
    size_t written = 0, other_written = 0, length = 0;

    CHECK_STATUS(NC_OK, nc_backup_seal(entropy, 32, password, strlen(password), sealed, sizeof sealed, &written));
    CHECK(written == NC_BACKUP_MAX_LENGTH);
    CHECK_STATUS(NC_OK, nc_backup_open(sealed, written, password, strlen(password), opened, sizeof opened, &length));
    CHECK(length == 32 && memcmp(opened, entropy, 32) == 0);

    /* Fresh salt and nonce every time: the same entropy seals differently. */
    CHECK_STATUS(NC_OK, nc_backup_seal(entropy, 32, password, strlen(password), other, sizeof other, &other_written));
    CHECK(other_written == written && memcmp(other, sealed, written) != 0);

    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_backup_open(sealed, written, "wrong", 5, opened, sizeof opened, &length));
    sealed[NC_BACKUP_HEADER_LENGTH] ^= 1;
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED,
                 nc_backup_open(sealed, written, password, strlen(password), opened, sizeof opened, &length));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_backup_open(sealed, written, password, strlen(password), opened, 31, &length));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_backup_seal(entropy, 32, password, 0, sealed, NC_BACKUP_MAX_LENGTH - 1, &written));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_seal(entropy, 15, password, 0, sealed, sizeof sealed, &written));
    memset(opened, 0, sizeof opened);

    /* What a backup sealed under a password says, and what opening it under a key does. */
    uint32_t kdf = 0;
    uint8_t key[NC_BACKUP_KEY_LENGTH];
    memset(key, 0x42, sizeof key);
    CHECK_STATUS(NC_OK, nc_backup_kdf(other, other_written, &kdf));
    CHECK(kdf == NC_BACKUP_KDF_ARGON2ID);
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_open_with_key(other, other_written, key, 32, opened, sizeof opened, &length));
}

/* A backup sealed under a 32-byte key, as a passkey's PRF gives one: sealed, opened, and refused every other way. */
static void test_backup_with_key(void) {
    static const uint8_t entropy[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
    uint8_t key[NC_BACKUP_KEY_LENGTH], wrong[NC_BACKUP_KEY_LENGTH], zero[NC_BACKUP_KEY_LENGTH] = {0};
    uint8_t sealed[NC_BACKUP_MAX_LENGTH], other[NC_BACKUP_MAX_LENGTH], opened[NC_ENTROPY_MAX_LENGTH];
    size_t written = 0, other_written = 0, length = 0;
    uint32_t kdf = 0;
    CHECK_STATUS(NC_OK, nc_random_bytes(key, sizeof key));
    memcpy(wrong, key, sizeof key);
    wrong[0] ^= 1;

    CHECK_STATUS(NC_OK, nc_backup_seal_with_key(entropy, 16, key, 32, sealed, sizeof sealed, &written));
    CHECK(written == NC_BACKUP_KEY_HEADER_LENGTH + 16 + 16);
    CHECK(memcmp(sealed, "ncbk\x01\x02", 6) == 0);
    CHECK_STATUS(NC_OK, nc_backup_kdf(sealed, written, &kdf));
    CHECK(kdf == NC_BACKUP_KDF_KEY);
    CHECK_STATUS(NC_OK, nc_backup_open_with_key(sealed, written, key, 32, opened, sizeof opened, &length));
    CHECK(length == 16 && memcmp(opened, entropy, 16) == 0);
    CHECK_STATUS(NC_OK, nc_backup_seal_with_key(entropy, 16, key, 32, other, sizeof other, &other_written));
    CHECK(other_written == written && memcmp(other, sealed, written) != 0);

    /* A wrong key and a changed backup fail alike; a password cannot open it, nor it a password's backup. */
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_backup_open_with_key(sealed, written, wrong, 32, opened, sizeof opened, &length));
    other[NC_BACKUP_KEY_HEADER_LENGTH - 1] ^= 1;
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_backup_open_with_key(other, written, key, 32, opened, sizeof opened, &length));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_open(sealed, written, "pw", 2, opened, sizeof opened, &length));

    /* Lengths, buffers, a key of zeros, a header this engine does not read. */
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_seal_with_key(entropy, 16, key, 31, sealed, sizeof sealed, &length));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_seal_with_key(entropy, 15, key, 32, sealed, sizeof sealed, &length));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_seal_with_key(entropy, 16, zero, 32, sealed, sizeof sealed, &length));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_seal_with_key(entropy, 16, NULL, 32, sealed, sizeof sealed, &length));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_backup_seal_with_key(entropy, 16, key, 32, sealed, written - 1, &length));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_backup_open_with_key(sealed, written, key, 32, opened, 31, &length));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_open_with_key(sealed, written - 1, key, 32, opened, sizeof opened, &length));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_kdf(sealed, written - 1, &kdf));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_backup_kdf(sealed, 5, &kdf));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_kdf(sealed, written, NULL));
    sealed[4] = 2;
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_kdf(sealed, written, &kdf));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_backup_open_with_key(sealed, written, key, 32, opened, sizeof opened, &length));
    memset(opened, 0, sizeof opened);
    memset(key, 0, sizeof key);
}

/* The BIP-32 fingerprint of "abandon ... about" with no passphrase, as BIP-84's and BIP-86's examples show it. */
#define ABANDON_FINGERPRINT 0x73c5da0au

static void test_seed_and_ethereum_key(void) {
    uint32_t baseline = nc_handle_count();
    nc_handle seed = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, &seed));
    CHECK(seed != 0);
    uint32_t kind = 0, fingerprint = 0;
    CHECK_STATUS(NC_OK, nc_handle_kind(seed, &kind));
    CHECK(kind == NC_KIND_SEED);
    CHECK_STATUS(NC_OK, nc_seed_fingerprint(seed, &fingerprint));
    CHECK(fingerprint == ABANDON_FINGERPRINT);

    nc_handle key = 0;
    const char *path = "m/44'/60'/0'/0/0";
    CHECK_STATUS(NC_OK, nc_key_derive(seed, NC_SCHEME_BIP32_SECP256K1, path, strlen(path), &key));
    CHECK_STATUS(NC_OK, nc_handle_kind(key, &kind));
    CHECK(kind == NC_KIND_SECP256K1_KEY);

    /* The Ethereum address of this key is the last 20 bytes of Keccak-256 over the uncompressed point. */
    uint8_t uncompressed[65], digest[32];
    size_t written = 0;
    CHECK_STATUS(NC_OK, nc_key_public(key, 0, uncompressed, 65, &written));
    CHECK(written == 65);
    CHECK_STATUS(NC_OK, nc_hash(NC_HASH_KECCAK256, uncompressed + 1, 64, digest, 32));
    CHECK(equals_hex(digest + 12, "9858effd232b4033e47d90003d41ec34ecaeda94"));

    /* Sign, verify, recover. */
    uint8_t signature[65], recovered[65];
    CHECK_STATUS(NC_OK, nc_key_sign(key, digest, 32, signature, 65, &written));
    CHECK(written == 65 && signature[64] <= 1);
    CHECK_STATUS(NC_OK, nc_secp256k1_verify(uncompressed, 65, digest, 32, signature, 64));
    CHECK_STATUS(NC_OK, nc_secp256k1_recover(digest, 32, signature, 65, 0, recovered, 65, &written));
    CHECK(written == 65 && memcmp(recovered, uncompressed, 65) == 0);
    digest[0] ^= 1;
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_secp256k1_verify(uncompressed, 65, digest, 32, signature, 64));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_key_sign(key, digest, 31, signature, 65, &written));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_secp256k1_verify(uncompressed, 65, digest, 32, signature, 65));

    CHECK_STATUS(NC_OK, nc_handle_destroy(key));
    CHECK_STATUS(NC_OK, nc_handle_destroy(seed));
    CHECK(nc_handle_count() == baseline);
}

/* BIP-86's first receiving key of "abandon ... about": its internal and output keys, and a key path signature. */
static void test_taproot_key(void) {
    uint32_t baseline = nc_handle_count();
    nc_handle seed = 0, key = 0, ed25519 = 0;
    const char *path = "m/86'/0'/0'/0/0";
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, &seed));
    CHECK_STATUS(NC_OK, nc_key_derive(seed, NC_SCHEME_BIP32_SECP256K1, path, strlen(path), &key));

    uint8_t internal[32], output[33], compressed[33], sighash[32], signature[64];
    size_t written = 0;
    CHECK_STATUS(NC_OK, nc_key_public_xonly(key, internal, 32, &written));
    CHECK(written == 32 && equals_hex(internal, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"));
    CHECK_STATUS(NC_OK, nc_secp256k1_taproot_tweak(internal, 32, NULL, 0, output, 33, &written));
    CHECK(equals_hex(output + 1, "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"));
    /* The compressed public key tweaks to the same output key. */
    uint8_t again[33];
    CHECK_STATUS(NC_OK, nc_key_public(key, 1, compressed, 33, &written));
    CHECK_STATUS(NC_OK, nc_secp256k1_taproot_tweak(compressed, 33, NULL, 0, again, 33, &written));
    CHECK(memcmp(again, output, 33) == 0);

    memset(sighash, 0x5a, sizeof sighash);
    CHECK_STATUS(NC_OK, nc_key_sign_taproot(key, sighash, 32, NULL, 0, signature, 64, &written));
    CHECK(written == 64);
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(output + 1, 32, sighash, 32, signature, 64));
    CHECK_STATUS(NC_ERR_VERIFICATION_FAILED, nc_secp256k1_schnorr_verify(internal, 32, sighash, 32, signature, 64));

    /* Untweaked, any length: verifies under the internal key. Two signatures differ (fresh aux randomness). */
    uint8_t other[64];
    CHECK_STATUS(NC_OK, nc_key_sign_schnorr(key, sighash, 7, signature, 64, &written));
    CHECK_STATUS(NC_OK, nc_key_sign_schnorr(key, sighash, 7, other, 64, &written));
    CHECK(memcmp(signature, other, 64) != 0);
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(internal, 32, sighash, 7, signature, 64));
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(internal, 32, sighash, 7, other, 64));
    CHECK_STATUS(NC_OK, nc_key_sign_schnorr(key, NULL, 0, signature, 64, &written));
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(internal, 32, NULL, 0, signature, 64));

    /* With a merkle root: verifies under that output key. */
    uint8_t merkle_root[32];
    memset(merkle_root, 0x11, sizeof merkle_root);
    CHECK_STATUS(NC_OK, nc_key_sign_taproot(key, sighash, 32, merkle_root, 32, signature, 64, &written));
    CHECK_STATUS(NC_OK, nc_secp256k1_taproot_tweak(internal, 32, merkle_root, 32, output, 33, &written));
    CHECK_STATUS(NC_OK, nc_secp256k1_schnorr_verify(output + 1, 32, sighash, 32, signature, 64));

    /* Refusals: a sighash that is not 32 bytes, a merkle root that is not, a short buffer, other handles. */
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_key_sign_taproot(key, sighash, 31, NULL, 0, signature, 64, &written));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_key_sign_taproot(key, sighash, 32, merkle_root, 16, signature, 64, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_key_sign_schnorr(key, sighash, 32, signature, 63, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_key_public_xonly(key, internal, 31, &written));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_key_sign_schnorr(key, sighash, 32, signature, 64, NULL));
    CHECK_STATUS(NC_OK, nc_key_generate(NC_CURVE_ED25519, &ed25519));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_sign_schnorr(ed25519, sighash, 32, signature, 64, &written));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_sign_taproot(seed, sighash, 32, NULL, 0, signature, 64, &written));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_public_xonly(ed25519, internal, 32, &written));

    CHECK_STATUS(NC_OK, nc_handle_destroy(ed25519));
    CHECK_STATUS(NC_OK, nc_handle_destroy(key));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_sign_schnorr(key, sighash, 32, signature, 64, &written));
    CHECK_STATUS(NC_OK, nc_handle_destroy(seed));
    CHECK(nc_handle_count() == baseline);
}

/* BIP-84's account 0 of "abandon ... about": its extended public key, and the published keys below it. */
static void test_extended_public_key(void) {
    uint32_t baseline = nc_handle_count();
    nc_handle seed = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, &seed));

    uint8_t account[NC_EXTENDED_PUBLIC_KEY_LENGTH], child[NC_EXTENDED_PUBLIC_KEY_LENGTH];
    size_t written = 0;
    const char *path = "m/84'/0'/0'";
    CHECK_STATUS(NC_OK, nc_seed_extended_public(seed, path, strlen(path), account, sizeof account, &written));
    CHECK(written == NC_EXTENDED_PUBLIC_KEY_LENGTH);
    CHECK(account[0] == 3 && account[5] == 0x80 && account[8] == 0x00);

    /* Receiving 0 and 1, change 0: BIP-84's published public keys, from the account's extended key alone. */
    const char *steps[] = {"m/0/0", "m/0/1", "m/1/0"};
    const char *expected[] = {
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
    };
    for (size_t index = 0; index < 3; index++) {
        CHECK_STATUS(NC_OK, nc_bip32_public_derive(account, sizeof account, steps[index], strlen(steps[index]), child,
                                                  sizeof child, &written));
        CHECK(written == NC_EXTENDED_PUBLIC_KEY_LENGTH && child[0] == 5);
        CHECK(equals_hex(child + 41, expected[index]));
    }

    /* The same key the private derivation gives, by the other road. */
    nc_handle key = 0;
    uint8_t public_key[33];
    const char *full = "m/84'/0'/0'/1/0";
    CHECK_STATUS(NC_OK, nc_key_derive(seed, NC_SCHEME_BIP32_SECP256K1, full, strlen(full), &key));
    CHECK_STATUS(NC_OK, nc_key_public(key, 1, public_key, sizeof public_key, &written));
    CHECK(memcmp(public_key, child + 41, 33) == 0);
    CHECK_STATUS(NC_OK, nc_handle_destroy(key));

    /* Refused: the master's, a hardened public step, short buffers, a wrong length, a key that is not a point. */
    CHECK_STATUS(NC_ERR_INVALID_PATH, nc_seed_extended_public(seed, "m", 1, account, sizeof account, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_seed_extended_public(seed, path, strlen(path), account, 73, &written));
    CHECK_STATUS(NC_ERR_INVALID_PATH, nc_bip32_public_derive(account, sizeof account, "m/0'", 4, child, sizeof child, &written));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_bip32_public_derive(account, sizeof account, "m/0", 3, child, 10, &written));
    CHECK_STATUS(NC_ERR_INVALID_LENGTH, nc_bip32_public_derive(account, 73, "m/0", 3, child, sizeof child, &written));
    account[41] = 0x07;
    CHECK_STATUS(NC_ERR_INVALID_PUBLIC_KEY, nc_bip32_public_derive(account, sizeof account, "m/0", 3, child, sizeof child, &written));

    CHECK_STATUS(NC_OK, nc_handle_destroy(seed));
    CHECK(nc_handle_count() == baseline);
}

static void test_solana_key(void) {
    nc_handle seed = 0, key = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, &seed));
    const char *normal = "m/44'/501'/0'/0";
    CHECK_STATUS(NC_ERR_INVALID_PATH, nc_key_derive(seed, NC_SCHEME_SLIP10_ED25519, normal, strlen(normal), &key));
    const char *path = "m/44'/501'/0'/0'";
    CHECK_STATUS(NC_OK, nc_key_derive(seed, NC_SCHEME_SLIP10_ED25519, path, strlen(path), &key));

    uint8_t public_key[32], signature[64];
    size_t written = 0;
    CHECK_STATUS(NC_OK, nc_key_public(key, 1, public_key, 32, &written));
    CHECK(written == 32);
    CHECK_STATUS(NC_OK, nc_key_sign(key, (const uint8_t *)"hello", 5, signature, 64, &written));
    CHECK_STATUS(NC_OK, nc_ed25519_verify(public_key, 32, (const uint8_t *)"hello", 5, signature, 64));
    CHECK_STATUS(NC_ERR_BUFFER_TOO_SMALL, nc_key_sign(key, (const uint8_t *)"hello", 5, signature, 63, &written));

    nc_handle_destroy(key);
    nc_handle_destroy(seed);
}

static void test_handle_lifecycle(void) {
    uint32_t baseline = nc_handle_count();
    nc_handle key = 0;
    uint8_t secret[32];
    memset(secret, 0x11, 32);
    CHECK_STATUS(NC_OK, nc_key_import(NC_CURVE_SECP256K1, secret, 32, &key));
    CHECK(nc_handle_count() == baseline + 1);

    CHECK_STATUS(NC_OK, nc_handle_destroy(key));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_handle_destroy(key));
    uint8_t out[65];
    size_t written;
    uint32_t kind;
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_public(key, 1, out, 65, &written));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_handle_kind(key, &kind));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_handle_destroy(0));
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_handle_destroy(~(nc_handle)0));

    /* The slot is reused with a new generation: the old handle still means nothing. */
    nc_handle again = 0;
    CHECK_STATUS(NC_OK, nc_key_import(NC_CURVE_SECP256K1, secret, 32, &again));
    CHECK(again != key);
    CHECK_STATUS(NC_ERR_INVALID_HANDLE, nc_key_public(key, 1, out, 65, &written));
    CHECK_STATUS(NC_OK, nc_handle_destroy(again));

    /* Nothing is stored when there is nowhere to put the handle. */
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_key_import(NC_CURVE_SECP256K1, secret, 32, NULL));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, NULL));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_key_generate(NC_CURVE_ED25519, NULL));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_key_generate(3, &key));
    CHECK_STATUS(NC_ERR_INVALID_ARGUMENT, nc_seed_generate(13, NULL, 0, &key));
    CHECK(nc_handle_count() == baseline);
}

static void test_handle_limit(void) {
    uint32_t baseline = nc_handle_count();
    uint32_t available = NC_HANDLE_CAPACITY - baseline;
    nc_handle *issued = calloc(available, sizeof(nc_handle));
    for (uint32_t i = 0; i < available; i++) CHECK_STATUS(NC_OK, nc_key_generate(NC_CURVE_ED25519, &issued[i]));
    nc_handle extra = 0;
    CHECK_STATUS(NC_ERR_HANDLE_LIMIT, nc_key_generate(NC_CURVE_ED25519, &extra));
    for (uint32_t i = 0; i < available; i++) CHECK_STATUS(NC_OK, nc_handle_destroy(issued[i]));
    CHECK(nc_handle_count() == baseline);
    free(issued);
}

static void test_repetition(void) {
    uint32_t baseline = nc_handle_count();
    uint8_t digest[32], signature[65], public_key[33];
    size_t written;
    for (int i = 0; i < 5000; i++) {
        nc_handle key = 0;
        CHECK_STATUS(NC_OK, nc_key_generate(NC_CURVE_SECP256K1, &key));
        nc_random_bytes(digest, 32);
        CHECK_STATUS(NC_OK, nc_key_sign(key, digest, 32, signature, 65, &written));
        CHECK_STATUS(NC_OK, nc_key_public(key, 1, public_key, 33, &written));
        CHECK_STATUS(NC_OK, nc_secp256k1_verify(public_key, 33, digest, 32, signature, 64));
        CHECK_STATUS(NC_OK, nc_handle_destroy(key));
    }
    CHECK(nc_handle_count() == baseline);
}

/* ------------------------------------------------------------------------------------------------ threads */

#define THREADS 8
#define ITERATIONS 300

typedef struct {
    nc_handle seed;
    int index;
    int errors;
} worker_t;

static void *worker(void *argument) {
    worker_t *job = argument;
    char path[64];
    for (int i = 0; i < ITERATIONS; i++) {
        snprintf(path, sizeof path, "m/44'/60'/%d'/0/%d", job->index, i);
        nc_handle key = 0;
        uint8_t digest[32], signature[65], public_key[33];
        size_t written;
        memset(digest, job->index, 32);
        if (nc_key_derive(job->seed, NC_SCHEME_BIP32_SECP256K1, path, strlen(path), &key) != NC_OK) job->errors++;
        if (nc_key_sign(key, digest, 32, signature, 65, &written) != NC_OK) job->errors++;
        if (nc_key_public(key, 1, public_key, 33, &written) != NC_OK) job->errors++;
        if (nc_secp256k1_verify(public_key, 33, digest, 32, signature, 64) != NC_OK) job->errors++;
        if (nc_handle_destroy(key) != NC_OK) job->errors++;
    }
    return NULL;
}

static void test_threads(void) {
    uint32_t baseline = nc_handle_count();
    nc_handle seed = 0;
    CHECK_STATUS(NC_OK, nc_seed_from_mnemonic(ABANDON, strlen(ABANDON), NULL, 0, &seed));

    pthread_t threads[THREADS];
    worker_t jobs[THREADS];
    for (int i = 0; i < THREADS; i++) {
        jobs[i] = (worker_t){.seed = seed, .index = i, .errors = 0};
        pthread_create(&threads[i], NULL, worker, &jobs[i]);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
        CHECK(jobs[i].errors == 0);
    }

    CHECK_STATUS(NC_OK, nc_handle_destroy(seed));
    CHECK(nc_handle_count() == baseline);
}

int main(void) {
    test_version_and_capabilities();
    test_status_names();
    test_random();
    test_hash();
    test_large_payload();
    test_hmac();
    test_secp256k1_public();
    test_ed25519_verify();
    test_schnorr_public();
    test_mnemonic();
    test_mnemonic_generate();
    test_entropy();
    test_backup();
    test_backup_with_key();
    test_seed_and_ethereum_key();
    test_taproot_key();
    test_extended_public_key();
    test_solana_key();
    test_handle_lifecycle();
    test_handle_limit();
    test_repetition();
    test_threads();

    if (failures > 0) {
        fprintf(stderr, "c_abi_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("c_abi_test: all checks passed\n");
    return 0;
}
