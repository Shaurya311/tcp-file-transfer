#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stddef.h>

/*
 * TCP is a byte stream: one recv() may return fewer bytes than asked for,
 * and one send() may accept fewer bytes than given. These helpers loop
 * until the full amount has been transferred.
 *
 * Both return 0 on success, -1 on error or if the peer closed the connection.
 */
int read_full(int fd, void *buf, size_t n);
int write_full(int fd, const void *buf, size_t n);

#endif
