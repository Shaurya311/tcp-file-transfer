CC      ?= gcc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra -pthread
LDFLAGS ?= -pthread

all: server client test_sha256

server: server.o sha256.o net_util.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client: client.o sha256.o net_util.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_sha256: test_sha256.o sha256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: all
	./test_sha256
	./test.sh

clean:
	rm -f *.o server client test_sha256
	rm -rf uploads test_tmp

.PHONY: all test clean
