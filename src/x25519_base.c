
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "common.h"

int
check_x25519_base_cb(char *parts[MAX_LINE_LENGTH])
{
    unsigned char *out;
    unsigned char *out2;    
    unsigned char *scalar;
    int            ret;

    out = sodium_malloc(crypto_scalarmult_BYTES);
    out2 = sodium_malloc(crypto_scalarmult_BYTES);    
    scalar = sodium_malloc(crypto_scalarmult_SCALARBYTES);
    sodium_hex2bin(scalar, crypto_scalarmult_SCALARBYTES,
                   parts[0], strlen(parts[0]), NULL, NULL, NULL);
    sodium_hex2bin(out, crypto_scalarmult_BYTES,
                   parts[1], strlen(parts[1]), NULL, NULL, NULL);
    crypto_scalarmult_base(out2, scalar);
    ret = memcmp(out, out2, crypto_scalarmult_BYTES);
    sodium_free(out2);
    sodium_free(out);
    sodium_free(scalar);    

    return ret;
}

int
check_x25519_base(void)
{
    parse_stdin(check_x25519_base_cb, 2);

    return 0;
}

int
main(void)
{
    if (sodium_init() != 0) {
        return -1;
    }
    check_x25519_base();

    return 0;
}
