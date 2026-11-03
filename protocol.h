#ifndef PROTOCOL_H
#define PROTOCOL_H

/*
 * Wire format (all integers big-endian / network byte order):
 *
 *   client -> server
 *     +-----------+-----------+-----------+----------------+-------------+
 *     | name_len  | file_size | file name | file bytes     | SHA-256     |
 *     | 2 bytes   | 8 bytes   | name_len  | file_size      | 32 bytes    |
 *     +-----------+-----------+-----------+----------------+-------------+
 *
 *   server -> client
 *     +--------+
 *     | status |   1 byte
 *     +--------+
 */

#define HEADER_LEN       10            /* 2 (name_len) + 8 (file_size)       */
#define MAX_NAME_LEN     255
#define MAX_FILE_SIZE    (1ULL << 30)  /* 1 GiB safety limit                 */
#define IO_CHUNK         (64 * 1024)

#define STATUS_OK        0   /* file stored and hash matched                 */
#define STATUS_BAD_HASH  1   /* hash did not match: file discarded           */
#define STATUS_BAD_REQ   2   /* invalid name or size                         */
#define STATUS_IO_ERROR  3   /* server could not write the file              */

#endif
