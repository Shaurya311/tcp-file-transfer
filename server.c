/*
 * Multi-client TCP file-transfer server.
 *
 * Usage: ./server <port> [upload_dir]
 *
 * One detached pthread is created per connected client. The only shared
 * state is the log output and the transfer counters, both protected by
 * a mutex.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "net_util.h"
#include "protocol.h"
#include "sha256.h"

typedef struct {
    int fd;
    char ip[INET_ADDRSTRLEN];
    int port;
} client_t;

static const char *upload_dir = "uploads";

/* Shared state: protected by log_mutex. */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long transfers_ok = 0;
static unsigned long transfers_failed = 0;

static void log_msg(const char *fmt, ...)
{
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);

    pthread_mutex_lock(&log_mutex);
    printf("[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

static void record_result(int ok)
{
    pthread_mutex_lock(&log_mutex);
    if (ok) transfers_ok++; else transfers_failed++;
    pthread_mutex_unlock(&log_mutex);
}

/* Reject anything that could escape the upload directory. */
static int valid_filename(const char *name, size_t len)
{
    if (len == 0 || len > MAX_NAME_LEN) return 0;
    if (strlen(name) != len) return 0;               /* embedded NUL byte  */
    if (strchr(name, '/') || strchr(name, '\\')) return 0;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    return 1;
}

static void send_status(int fd, uint8_t status)
{
    write_full(fd, &status, 1);
}

static void handle_transfer(client_t *cl)
{
    uint8_t hdr[HEADER_LEN];
    char name[MAX_NAME_LEN + 1];
    char final_path[1024], tmp_path[1100];
    uint8_t buf[IO_CHUNK];
    FILE *out = NULL;
    int ok = 0;

    /* 1. Fixed-size header: name length + file size. */
    if (read_full(cl->fd, hdr, HEADER_LEN) < 0) {
        log_msg("%s:%d disconnected before sending a header", cl->ip, cl->port);
        return;
    }
    uint16_t name_len = (uint16_t)((hdr[0] << 8) | hdr[1]);
    uint64_t size_be;
    memcpy(&size_be, hdr + 2, sizeof size_be);
    uint64_t file_size = be64toh(size_be);

    /* 2. File name. */
    if (name_len == 0 || name_len > MAX_NAME_LEN ||
        read_full(cl->fd, name, name_len) < 0) {
        send_status(cl->fd, STATUS_BAD_REQ);
        log_msg("%s:%d bad request (name length %u)", cl->ip, cl->port, name_len);
        return;
    }
    name[name_len] = '\0';

    if (!valid_filename(name, name_len) || file_size > MAX_FILE_SIZE) {
        send_status(cl->fd, STATUS_BAD_REQ);
        log_msg("%s:%d rejected request (name/size not allowed)", cl->ip, cl->port);
        return;
    }

    /* 3. Write to a temporary file; rename it only after the hash matches. */
    snprintf(final_path, sizeof final_path, "%s/%s", upload_dir, name);
    snprintf(tmp_path, sizeof tmp_path, "%s.part.%d", final_path, cl->fd);
    out = fopen(tmp_path, "wb");
    if (!out) {
        send_status(cl->fd, STATUS_IO_ERROR);
        log_msg("%s:%d cannot create %s: %s", cl->ip, cl->port, tmp_path, strerror(errno));
        return;
    }

    log_msg("%s:%d uploading '%s' (%llu bytes)", cl->ip, cl->port, name,
            (unsigned long long)file_size);

    /* 4. Receive the file in chunks, hashing as we go. */
    sha256_ctx ctx;
    sha256_init(&ctx);
    uint64_t remaining = file_size;
    while (remaining > 0) {
        size_t want = remaining < sizeof buf ? (size_t)remaining : sizeof buf;
        if (read_full(cl->fd, buf, want) < 0) {
            log_msg("%s:%d connection lost during '%s'", cl->ip, cl->port, name);
            goto cleanup;
        }
        if (fwrite(buf, 1, want, out) != want) {
            send_status(cl->fd, STATUS_IO_ERROR);
            log_msg("%s:%d write error on '%s'", cl->ip, cl->port, name);
            goto cleanup;
        }
        sha256_update(&ctx, buf, want);
        remaining -= want;
    }
    uint8_t computed[SHA256_DIGEST_LEN];
    sha256_final(&ctx, computed);

    /* 5. Compare with the digest the client sent. */
    uint8_t claimed[SHA256_DIGEST_LEN];
    if (read_full(cl->fd, claimed, sizeof claimed) < 0) {
        log_msg("%s:%d connection lost before hash for '%s'", cl->ip, cl->port, name);
        goto cleanup;
    }

    if (fclose(out) != 0) {
        out = NULL;
        send_status(cl->fd, STATUS_IO_ERROR);
        goto cleanup;
    }
    out = NULL;

    if (memcmp(computed, claimed, SHA256_DIGEST_LEN) != 0) {
        send_status(cl->fd, STATUS_BAD_HASH);
        log_msg("%s:%d HASH MISMATCH for '%s' - discarded", cl->ip, cl->port, name);
        goto cleanup;
    }

    if (rename(tmp_path, final_path) != 0) {
        send_status(cl->fd, STATUS_IO_ERROR);
        log_msg("%s:%d rename failed for '%s': %s", cl->ip, cl->port, name, strerror(errno));
        goto cleanup;
    }

    char hex[65];
    sha256_to_hex(computed, hex);
    send_status(cl->fd, STATUS_OK);
    log_msg("%s:%d stored '%s' sha256=%s", cl->ip, cl->port, name, hex);
    ok = 1;

cleanup:
    if (out) fclose(out);
    if (!ok) unlink(tmp_path);
    record_result(ok);
}

static void *client_thread(void *arg)
{
    client_t *cl = arg;
    handle_transfer(cl);
    close(cl->fd);
    free(cl);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <port> [upload_dir]\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[1]);
        return 1;
    }
    if (argc == 3) upload_dir = argv[2];

    if (mkdir(upload_dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir upload_dir");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }

    log_msg("listening on port %d, saving to '%s'", port, upload_dir);

    for (;;) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof caddr;
        int fd = accept(srv, (struct sockaddr *)&caddr, &clen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        client_t *cl = malloc(sizeof *cl);
        if (!cl) { close(fd); continue; }
        cl->fd = fd;
        inet_ntop(AF_INET, &caddr.sin_addr, cl->ip, sizeof cl->ip);
        cl->port = ntohs(caddr.sin_port);

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, cl) != 0) {
            log_msg("pthread_create failed");
            close(fd);
            free(cl);
            continue;
        }
        pthread_detach(tid);   /* no join needed: thread cleans up after itself */
    }
}
