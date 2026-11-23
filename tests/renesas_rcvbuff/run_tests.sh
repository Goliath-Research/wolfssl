#!/bin/sh
# Fails while a sample writes a NUL at the full read length of a 256-byte
# stack buffer. Passes once that store stays inside the array.
set -u

OUT="${OUT:-/tmp/renesas-rcvbuff-tests}"
PORT=11111
FAIL=0

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:halt_on_error=1}"
export LD_LIBRARY_PATH="${WOLFSSL_BUILD:-/tmp/wolfssl-build}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

wait_ready() {
    err=$1
    i=0
    while [ "$i" -lt 100 ]; do
        if grep -q SERVER_READY "$err"; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "server exited before ready"
            cat "$err"
            return 1
        fi
        i=$((i + 1))
        sleep 0.05
    done
    echo "server did not become ready"
    cat "$err"
    return 1
}

run_tls() {
    name=$1
    mode=$2
    nbytes=$3
    client=$4
    expect_dial=$5
    expect=$6

    echo "=== $name mode=$mode bytes=$nbytes expect=$expect ==="
    serr=$(mktemp)
    cout=$(mktemp)
    cerr=$(mktemp)
    "$OUT/payload_server" "$mode" "$nbytes" "$PORT" >"$cout.server" 2>"$serr" &
    SERVER_PID=$!
    if ! wait_ready "$serr"; then
        FAIL=1
        wait "$SERVER_PID" 2>/dev/null || true
        rm -f "$serr" "$cout" "$cerr" "$cout.server"
        return
    fi
    "$client" >"$cout" 2>"$cerr"
    client_rc=$?
    wait "$SERVER_PID"
    server_rc=$?

    echo "client_rc=$client_rc server_rc=$server_rc"
    echo "-- client stderr --"
    cat "$cerr"
    echo "-- client stdout --"
    cat "$cout"
    echo "-- server stderr --"
    cat "$serr"

    ok=1
    if [ -n "$expect_dial" ]; then
        if ! grep -q "DIAL $expect_dial" "$cerr"; then
            echo "FAIL $name: dial was not '$expect_dial'"
            ok=0
        fi
    fi
    case "$expect" in
    safe)
        if [ "$client_rc" -ne 0 ]; then
            echo "FAIL $name: client exited $client_rc"
            ok=0
        fi
        if ! grep -q "Received:" "$cout"; then
            echo "FAIL $name: payload was not delivered to the sample"
            ok=0
        fi
        ;;
    rejected)
        if [ "$client_rc" -ne 0 ]; then
            echo "FAIL $name: untrusted peer aborted the client ($client_rc)"
            ok=0
        fi
        if grep -q "Received:" "$cout"; then
            echo "FAIL $name: untrusted peer was accepted"
            ok=0
        fi
        ;;
    esac
    if [ "$ok" -eq 0 ]; then
        FAIL=1
    else
        echo "PASS $name"
    fi
    rm -f "$serr" "$cout" "$cerr" "$cout.server"
}

run_tcp() {
    name=$1
    nbytes=$2
    expect_dial=$3

    echo "=== $name bytes=$nbytes ==="
    serr=$(mktemp)
    cout=$(mktemp)
    cerr=$(mktemp)
    "$OUT/tcp_payload_server" "$nbytes" "$PORT" >"$cout.server" 2>"$serr" &
    SERVER_PID=$!
    if ! wait_ready "$serr"; then
        FAIL=1
        wait "$SERVER_PID" 2>/dev/null || true
        rm -f "$serr" "$cout" "$cerr" "$cout.server"
        return
    fi
    "$OUT/client_rx72n_tcp" >"$cout" 2>"$cerr"
    client_rc=$?
    wait "$SERVER_PID" || true
    echo "client_rc=$client_rc"
    cat "$cerr"
    cat "$cout"
    ok=1
    if ! grep -q "DIAL $expect_dial" "$cerr"; then
        echo "FAIL $name: dial was not '$expect_dial'"
        ok=0
    fi
    if [ "$client_rc" -ne 0 ] || ! grep -q "Received:" "$cout"; then
        echo "FAIL $name"
        ok=0
    fi
    if [ "$ok" -eq 0 ]; then
        FAIL=1
    else
        echo "PASS $name"
    fi
    rm -f "$serr" "$cout" "$cerr" "$cout.server"
}

# Short payloads stay inside the 256-byte array on the unfixed samples.
run_tls t4_short trusted 4 "$OUT/client_t4" "127.0.0.1 11111" safe
run_tls projects_short trusted 4 "$OUT/client_projects" "192.168.1.45 11111" safe
run_tls grrose_short trusted 4 "$OUT/client_grrose" "192.168.1.12 11111" safe
run_tls rx72n_tls_short trusted 4 "$OUT/client_rx72n_tls" "192.168.11.6 11111" safe
run_tls ra6m4_short trusted 4 "$OUT/client_ra6m4" "192.168.11.4 11111" safe
run_tls rzn2l_short trusted 4 "$OUT/client_rzn2l" "192.168.11.65 11111" safe
run_tcp rx72n_tcp_short 4 "192.168.10.10 11111"

# 255 bytes is the last in-range index. 256 is one past the array.
run_tls t4_255 trusted 255 "$OUT/client_t4" "127.0.0.1 11111" safe
run_tls t4_full trusted 256 "$OUT/client_t4" "127.0.0.1 11111" safe
run_tls projects_full trusted 256 "$OUT/client_projects" "192.168.1.45 11111" safe
run_tls grrose_full trusted 256 "$OUT/client_grrose" "192.168.1.12 11111" safe
run_tls rx72n_tls_full trusted 256 "$OUT/client_rx72n_tls" "192.168.11.6 11111" safe
run_tls ra6m4_full trusted 256 "$OUT/client_ra6m4" "192.168.11.4 11111" safe
run_tls rzn2l_full trusted 256 "$OUT/client_rzn2l" "192.168.11.65 11111" safe
run_tcp rx72n_tcp_full 256 "192.168.10.10 11111"

# A certificate the loaded CA does not sign must not reach the read.
run_tls t4_untrusted untrusted 256 "$OUT/client_t4" "127.0.0.1 11111" rejected

if [ "$FAIL" -ne 0 ]; then
    echo "TESTS FAILED"
    exit 1
fi
echo "TESTS PASSED"
exit 0
