#!/bin/sh
# Build the INtime sample client against this tree and run the full-buffer
# receive print test. Exit 0 once the printed buffer is terminated inside
# its 4096 bytes. Exit 1 while the vulnerability is present.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
BUILD=${BUILD:-/tmp/wolfssl-intime-rcv-overread}

cmake -S "$ROOT" -B "$BUILD" \
    -DWOLFSSL_EXAMPLES=no \
    -DWOLFSSL_CRYPT_TESTS=no \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD" -j"$(nproc)"

cc -O0 -fno-builtin-printf -g \
    -I"$ROOT/IDE/INTIME-RTOS/tests" \
    -I"$BUILD" \
    -I"$ROOT" \
    -DWOLFSSL_USE_OPTIONS_H \
    -DUSE_CERT_BUFFERS_2048 \
    -DWOLF_EXAMPLES_STACK=131072 \
    -Dmain=wolfexamples_sample_main \
    -c "$ROOT/IDE/INTIME-RTOS/wolfExamples.c" \
    -o "$BUILD/wolfExamples.o"

cc -O0 -fno-builtin-printf -g \
    -I"$BUILD" \
    -I"$ROOT" \
    -DWOLFSSL_USE_OPTIONS_H \
    -DUSE_CERT_BUFFERS_2048 \
    -o "$BUILD/intime_rcv_overread" \
    "$ROOT/IDE/INTIME-RTOS/tests/test_rcv_overread.c" \
    "$BUILD/wolfExamples.o" \
    "$BUILD/libwolfssl.a" \
    -pthread \
    -lm \
    -Wl,--wrap=printf

cd "$ROOT"
exec "$BUILD/intime_rcv_overread"
