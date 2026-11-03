/*
 * Client for the TCP file-transfer server.
 *
 * Usage: ./client <host> <port> <file>
 * Exit code 0 only if the server confirms the file arrived intact.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net_util.h"
#include "protocol.h"
#include "sha256.h"

static int connect_to(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <host> <port> <file>\n", argv[0]);
        return 2;
    }
    const char *path = argv[3];

    int in = open(path, O_RDONLY);
    if (in < 0) { perror("open"); return 2; }

    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular file\n", path);
        return 2;
    }

    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > MAX_NAME_LEN) {
        fprintf(stderr, "File name length must be 1..%d\n", MAX_NAME_LEN);
        return 2;
    }

    int fd = connect_to(argv[1], argv[2]);
    if (fd < 0) { fprintf(stderr, "could not connect to %s:%s\n", argv[1], argv[2]); return 2; }

    /* Header: name_len (2 bytes) + file_size (8 bytes), big-endian. */
    uint8_t hdr[HEADER_LEN];
    hdr[0] = (uint8_t)(name_len >> 8);
    hdr[1] = (uint8_t)(name_len & 0xff);
    uint64_t size_be = htobe64((uint64_t)st.st_size);
    memcpy(hdr + 2, &size_be, sizeof size_be);

    if (write_full(fd, hdr, HEADER_LEN) < 0 || write_full(fd, name, name_len) < 0) {
        fprintf(stderr, "failed to send header\n");
        return 2;
    }

    /* File body, hashing while sending. */
    sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[IO_CHUNK];
    uint64_t remaining = (uint64_t)st.st_size;
    while (remaining > 0) {
        size_t want = remaining < sizeof buf ? (size_t)remaining : sizeof buf;
        ssize_t r = read(in, buf, want);
        if (r <= 0) { fprintf(stderr, "read error on '%s'\n", path); return 2; }
        if (write_full(fd, buf, (size_t)r) < 0) {
            fprintf(stderr, "connection lost while sending\n");
            return 2;
        }
        sha256_update(&ctx, buf, (size_t)r);
        remaining -= (uint64_t)r;
    }
    close(in);

    uint8_t digest[SHA256_DIGEST_LEN];
    sha256_final(&ctx, digest);
    if (write_full(fd, digest, sizeof digest) < 0) {
        fprintf(stderr, "failed to send hash\n");
        return 2;
    }

    /* Wait for the server's verdict. */
    uint8_t status;
    if (read_full(fd, &status, 1) < 0) {
        fprintf(stderr, "no reply from server\n");
        return 2;
    }
    close(fd);

    char hex[65];
    sha256_to_hex(digest, hex);
    switch (status) {
    case STATUS_OK:
        printf("OK: '%s' (%lld bytes) stored, sha256=%s\n", name, (long long)st.st_size, hex);
        return 0;
    case STATUS_BAD_HASH:
        fprintf(stderr, "FAILED: server reports hash mismatch\n");
        return 1;
    case STATUS_BAD_REQ:
        fprintf(stderr, "FAILED: server rejected the request\n");
        return 1;
    default:
        fprintf(stderr, "FAILED: server I/O error\n");
        return 1;
    }
}
