#!/usr/bin/env bash
# End-to-end test: start the server, upload several files in parallel,
# and confirm every stored file is byte-identical to its original.
set -u

PORT=${PORT:-5055}
TMP=test_tmp
UP="$TMP/uploads"
SRC="$TMP/src"
FAILS=0

cleanup() { [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

rm -rf "$TMP"; mkdir -p "$SRC" "$UP"

# Test files: empty, tiny, not block-aligned, and large.
: > "$SRC/empty.bin"
printf 'x' > "$SRC/one_byte.bin"
head -c 100003  /dev/urandom > "$SRC/odd_size.bin"
head -c 5242880 /dev/urandom > "$SRC/five_mb.bin"
head -c 20971520 /dev/urandom > "$SRC/twenty_mb.bin"

./server "$PORT" "$UP" > "$TMP/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

echo "== Uploading files in parallel"
pids=()
for f in "$SRC"/*; do
    ./client 127.0.0.1 "$PORT" "$f" > "$TMP/$(basename "$f").out" 2>&1 &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || FAILS=$((FAILS+1)); done

echo "== Verifying stored files"
for f in "$SRC"/*; do
    name=$(basename "$f")
    if cmp -s "$f" "$UP/$name"; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"; FAILS=$((FAILS+1))
    fi
done

echo "== Rejecting a path-traversal name"
# Client strips directories, so craft the request by hand with a bad name.
python3 - "$PORT" << 'PY'
import socket, struct, sys
port = int(sys.argv[1])
name = b"../evil.txt"
s = socket.create_connection(("127.0.0.1", port))
s.sendall(struct.pack(">HQ", len(name), 4) + name)
status = s.recv(1)
print("PASS  traversal rejected" if status == b"\x02" else "FAIL  traversal accepted")
sys.exit(0 if status == b"\x02" else 1)
PY
[ $? -eq 0 ] || FAILS=$((FAILS+1))
[ -e "$TMP/evil.txt" ] && { echo "FAIL  evil.txt was written"; FAILS=$((FAILS+1)); }

echo "== Detecting a corrupted hash"
python3 - "$PORT" << 'PY'
import socket, struct, sys
port = int(sys.argv[1])
name, data = b"corrupt.bin", b"hello world"
s = socket.create_connection(("127.0.0.1", port))
s.sendall(struct.pack(">HQ", len(name), len(data)) + name + data + b"\x00" * 32)
status = s.recv(1)
print("PASS  bad hash detected" if status == b"\x01" else "FAIL  bad hash accepted")
sys.exit(0 if status == b"\x01" else 1)
PY
[ $? -eq 0 ] || FAILS=$((FAILS+1))
[ -e "$UP/corrupt.bin" ] && { echo "FAIL  corrupt file was kept"; FAILS=$((FAILS+1)); }

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "$FAILS TEST(S) FAILED"; fi
exit "$FAILS"
