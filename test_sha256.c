/*
 * Checks sha256.c against the official NIST / FIPS 180-4 test vectors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

static int failures = 0;

static void check(const char *label, const void *data, size_t len, const char *expected)
{
    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_LEN];
    char hex[65];

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
    sha256_to_hex(digest, hex);

    if (strcmp(hex, expected) == 0) {
        printf("PASS  %s\n", label);
    } else {
        printf("FAIL  %s\n  expected %s\n  got      %s\n", label, expected, hex);
        failures++;
    }
}

int main(void)
{
    check("empty string", "", 0,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    check("\"abc\"", "abc", 3,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char *two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check("448-bit message (forces an extra padding block)", two_block, strlen(two_block),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* One million 'a' characters. */
    char *million = malloc(1000000);
    memset(million, 'a', 1000000);
    check("one million 'a'", million, 1000000,
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    /* Streaming: feeding data in awkward pieces must give the same hash. */
    sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_LEN];
    char hex[65];
    sha256_init(&ctx);
    size_t pos = 0, step = 1;
    while (pos < 1000000) {
        size_t n = step < 1000000 - pos ? step : 1000000 - pos;
        sha256_update(&ctx, million + pos, n);
        pos += n;
        step = step % 97 + 1;          /* chunk sizes 1..97, never block-aligned */
    }
    sha256_final(&ctx, digest);
    sha256_to_hex(digest, hex);
    if (strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0) {
        printf("PASS  streaming in uneven chunks\n");
    } else {
        printf("FAIL  streaming in uneven chunks (got %s)\n", hex);
        failures++;
    }
    free(million);

    printf(failures ? "\n%d test(s) FAILED\n" : "\nAll SHA-256 tests passed\n", failures);
    return failures ? 1 : 0;
}
