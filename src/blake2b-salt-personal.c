
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "common.h"

#define MAX_MESSAGE_LENGTH 256

int
check_blake2b_cb(char *parts[MAX_LINE_LENGTH])
{
    unsigned char *out;
    unsigned char *out2;
    unsigned char *message;
    unsigned char *key;
    unsigned char *salt;
    unsigned char *personal;
    size_t         message_len;
    size_t         out_len;
    size_t         out2_len;
    size_t         key_len;
    int            ret;

    out = sodium_malloc(crypto_generichash_blake2b_BYTES_MAX);
    out2 = sodium_malloc(crypto_generichash_blake2b_BYTES_MAX);
    message = sodium_malloc(MAX_MESSAGE_LENGTH);
    key = sodium_malloc(crypto_generichash_blake2b_KEYBYTES_MAX);
    salt = sodium_malloc(crypto_generichash_blake2b_SALTBYTES);
    personal = sodium_malloc(crypto_generichash_blake2b_PERSONALBYTES);
    sodium_hex2bin(message, MAX_MESSAGE_LENGTH, parts[0], strlen(parts[0]),
                   NULL, &message_len, NULL);
    sodium_hex2bin(key, crypto_generichash_blake2b_KEYBYTES_MAX,
                   parts[1], strlen(parts[1]), NULL, &key_len, NULL);
    sodium_hex2bin(salt, crypto_generichash_blake2b_SALTBYTES,
                   parts[2], strlen(parts[2]), NULL, NULL, NULL);
    sodium_hex2bin(personal, crypto_generichash_blake2b_PERSONALBYTES,
                   parts[3], strlen(parts[3]), NULL, NULL, NULL);
    out2_len = (size_t) strtoul(parts[4], NULL, 10);
    sodium_hex2bin(out, crypto_generichash_blake2b_BYTES_MAX,
                   parts[5], strlen(parts[5]), NULL, &out_len, NULL);
    assert(out_len == out2_len);
    crypto_generichash_blake2b_salt_personal(out2, out2_len,
                                             message, message_len,
                                             key, key_len, salt, personal);
    ret = memcmp(out, out2, out_len);
    sodium_free(personal);
    sodium_free(salt);
    sodium_free(key);
    sodium_free(message);
    sodium_free(out2);
    sodium_free(out);

    return ret;
}

int
check_blake2b(void)
{
    parse_stdin(check_blake2b_cb, 6);

    return 0;
}

int
main(void)
{
    sodium_init();
    check_blake2b();

    return 0;
}
