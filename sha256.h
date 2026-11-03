#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];   /* running hash values H0..H7              */
    uint64_t total;      /* total number of bytes processed so far  */
    uint8_t  buf[64];    /* partial block waiting to be processed   */
    size_t   buflen;     /* how many bytes are in buf               */
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_LEN]);

/* Convenience: write digest as 64 hex chars + NUL into out[65]. */
void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_LEN], char out[65]);

#endif
