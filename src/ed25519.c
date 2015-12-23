
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "common.h"

#define MAX_MESSAGE_LENGTH 256

int
check_ed25519_cb(char *parts[MAX_LINE_LENGTH])
{
    unsigned char *out;
    unsigned char *out2;
    unsigned char *message;
    unsigned char *pk;
    unsigned char *pk2;
    unsigned char *seed;
    unsigned char *sk;
    size_t         message_len;
    size_t         out_len;
    size_t         sk_len;
    int            ret;

    out = sodium_malloc(crypto_sign_BYTES);
    out2 = sodium_malloc(crypto_sign_BYTES);
    message = sodium_malloc(MAX_MESSAGE_LENGTH);
    pk = sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    pk2 = sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    seed = sodium_malloc(crypto_sign_SEEDBYTES);
    sk = sodium_malloc(crypto_sign_SECRETKEYBYTES);
    sodium_hex2bin(message, MAX_MESSAGE_LENGTH, parts[0], strlen(parts[0]),
                   NULL, &message_len, NULL);
    sodium_hex2bin(sk, crypto_sign_SECRETKEYBYTES,
                   parts[1], strlen(parts[1]), NULL, &sk_len, NULL);
    assert(sk_len == crypto_sign_SECRETKEYBYTES);
    sodium_hex2bin(out, crypto_sign_BYTES,
                   parts[2], strlen(parts[2]), NULL, &out_len, NULL);
    assert(out_len == crypto_sign_BYTES);
    crypto_sign_detached(out2, NULL, message, message_len, sk);
    ret = memcmp(out, out2, crypto_sign_BYTES);

    crypto_sign_ed25519_sk_to_pk(pk2, sk);
    crypto_sign_ed25519_sk_to_seed(seed, sk);
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);

    ret |= memcmp(pk, pk2, crypto_sign_PUBLICKEYBYTES);
    ret |= crypto_sign_verify_detached(out2, message, message_len, pk);

    sodium_free(sk);
    sodium_free(seed);
    sodium_free(pk);
    sodium_free(pk2);
    sodium_free(message);
    sodium_free(out2);
    sodium_free(out);

    return ret;
}

int
check_ed25519(void)
{
    parse_stdin(check_ed25519_cb, 3);

    return 0;
}

int
main(void)
{
    if (sodium_init() != 0) {
        return -1;
    }
    check_ed25519();

    return 0;
}
