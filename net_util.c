#include "net_util.h"

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t got = 0;

    while (got < n) {
        ssize_t r = recv(fd, p + got, n - got, 0);
        if (r == 0)
            return -1;              /* peer closed before sending everything */
        if (r < 0) {
            if (errno == EINTR)
                continue;           /* interrupted by a signal: retry */
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t sent = 0;

    while (sent < n) {
        /* MSG_NOSIGNAL: return EPIPE instead of killing us with SIGPIPE. */
        ssize_t r = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}
