
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "common.h"

#define MAX_MESSAGE_LENGTH 256

int
check_sha256_cb(char *parts[MAX_LINE_LENGTH])
{
    unsigned char *out;
    unsigned char *out2;
    unsigned char *message;
    size_t         message_len;
    size_t         out_len;
    int            ret;

    out = sodium_malloc(crypto_hash_sha256_BYTES);
    out2 = sodium_malloc(crypto_hash_sha256_BYTES);
    message = sodium_malloc(MAX_MESSAGE_LENGTH);
    sodium_hex2bin(message, MAX_MESSAGE_LENGTH, parts[0], strlen(parts[0]),
                   NULL, &message_len, NULL);
    sodium_hex2bin(out, crypto_hash_sha256_BYTES, parts[1], strlen(parts[1]),
                   NULL, &out_len, NULL);
    assert(out_len == crypto_hash_sha256_BYTES);
    crypto_hash_sha256(out2, message, message_len);
    ret = memcmp(out, out2, crypto_hash_sha256_BYTES);
    sodium_free(message);
    sodium_free(out2);
    sodium_free(out);

    return ret;
}

int
check_sha256(void)
{
    parse_stdin(check_sha256_cb, 2);

    return 0;
}

int
main(void)
{
    if (sodium_init() != 0) {
        return 1;
    }
    check_sha256();

    return 0;
}
