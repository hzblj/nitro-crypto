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
    test_mnemonic();
    test_mnemonic_generate();
    test_seed_and_ethereum_key();
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
