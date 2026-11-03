#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: sudo $0 --source SMITHPROXY_SOURCE --binary SMITHPROXY_BINARY [--work-dir DIR] [--scenario NAME]" >&2
}

SOURCE=
BINARY=
WORK_DIR=
SCENARIO=
while (($#)); do
    case "$1" in
        --source) SOURCE=${2:?missing source path}; shift 2 ;;
        --binary) BINARY=${2:?missing binary path}; shift 2 ;;
        --work-dir) WORK_DIR=${2:?missing work directory}; shift 2 ;;
        --scenario) SCENARIO=${2:?missing scenario name}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

((EUID == 0)) || { echo "run this isolated network lab through sudo" >&2; exit 2; }
[[ -n $SOURCE && -d $SOURCE/tests/patch-runner ]] || { echo "invalid Smithproxy source: $SOURCE" >&2; exit 2; }
[[ -x $BINARY ]] || { echo "invalid Smithproxy binary: $BINARY" >&2; exit 2; }
[[ -z $SCENARIO || $SCENARIO =~ ^[a-zA-Z0-9_-]+$ ]] || {
    echo "invalid scenario name: $SCENARIO" >&2
    exit 2
}

PN_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
PN=$PN_ROOT/build/pn
[[ -x $PN ]] || { echo "ProxyNightmare binary is missing: $PN" >&2; exit 2; }

if [[ -z $WORK_DIR ]]; then
    WORK_DIR=$PN_ROOT/build/smithproxy-lab-$(date -u +%Y%m%dT%H%M%SZ)
fi
mkdir -p "$WORK_DIR/bin" "$WORK_DIR/runner/tests" "$WORK_DIR/corpus" \
         "$WORK_DIR/src/etc/msg/en" "$WORK_DIR/results"
ln -s "$BINARY" "$WORK_DIR/bin/smithproxy"
cp "$SOURCE/tests/patch-runner/smithproxy.runner" "$WORK_DIR/runner/"
cp -a "$SOURCE/tests/patch-runner/harness/." "$WORK_DIR/runner/tests/"
cp -a "$SOURCE/tests/patch-runner/corpus/." "$WORK_DIR/corpus/"
cp "$SOURCE/tests/patch-runner/vendor/pplay.py" "$WORK_DIR/pplay.py"
cp "$SOURCE/etc/smithproxy.cfg" "$WORK_DIR/src/etc/"
cp -a "$SOURCE/etc/msg/en/." "$WORK_DIR/src/etc/msg/en/"

# PN creates a fresh self-signed origin certificate for every TLS scenario.
# Keep the real default MITM profile active, but let this isolated test profile
# accept that ephemeral origin identity. The PN client cryptographically checks
# CertificateVerify and Finished, while intentionally using no public trust store.
sed -i \
    -e 's/allow_invalid_certs = FALSE/allow_invalid_certs = TRUE/' \
    -e 's/allow_self_signed = FALSE/allow_self_signed = TRUE/' \
    "$WORK_DIR/src/etc/smithproxy.cfg"

LAB_PID=
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n $LAB_PID ]] && kill -0 "$LAB_PID" 2>/dev/null; then
        kill -TERM "$LAB_PID" 2>/dev/null || true
        wait "$LAB_PID" 2>/dev/null || true
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

env CLIENT_NS=sxr-client SERVER_NS=sxr-origin DATA_NS=sxr-data \
    LAB_IN_IF=sxrpi LAB_OUT_IF=sxrpo LAB_API_PORT=55586 LAB_CLI_PORT=55587 \
    RUN_MODE=1 BASE_TRAFFIC_TEST=0 CAPTURE_TEST=0 \
    "$WORK_DIR/runner/tests/lab-test.sh" "$WORK_DIR" \
    > "$WORK_DIR/results/lab-console.log" 2>&1 &
LAB_PID=$!

ready=0
for _ in $(seq 1 120); do
    if grep -q 'Smithproxy interactive lab READY' "$WORK_DIR/results/lab-console.log"; then
        ready=1
        break
    fi
    kill -0 "$LAB_PID"
    sleep 1
done
if ((ready == 0)); then
    echo "Smithproxy lab did not become ready" >&2
    tail -80 "$WORK_DIR/results/lab-console.log" >&2
    exit 1
fi

# The stock P3 origin owns 198.18.20.2:443. Stop only that copied harness
# process; PN TLS scenarios bind the same address while the lab is active.
for pid in $(ip netns pids sxr-origin); do
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [[ $cmdline == *"$WORK_DIR/runner/tests/origin.py"* ]]; then
        kill -TERM "$pid"
    fi
done
for _ in $(seq 1 50); do
    if ! ip netns exec sxr-origin ss -ltnH 'sport = :443' | grep -q .; then
        break
    fi
    sleep 0.1
done
if ip netns exec sxr-origin ss -ltnH 'sport = :443' | grep -q .; then
    echo "P3 origin did not release 198.18.20.2:443" >&2
    exit 1
fi

echo "Smithproxy lab ready: $WORK_DIR"
count=0
failed=0
declare -A task_cpu_before=()
printf 'scenario\tresult\trc\n' > "$WORK_DIR/results/pn-summary.tsv"
while IFS= read -r scenario; do
    name=$(basename "$scenario" .pn)
    log="$WORK_DIR/results/pn-$name.log"
    echo "=== $name ==="
    cpu_before=
    if [[ $name == tls_idle_after_close_notify ]]; then
        proxy_pid=$(sed -n 's/.*proxy PID=\([0-9][0-9]*\).*/\1/p' "$WORK_DIR/results/runner.log" | tail -1)
        [[ -n $proxy_pid && -r /proc/$proxy_pid/stat ]] || {
            echo "cannot locate Smithproxy PID for idle-spin detection" >&2
            exit 1
        }
        read -r _ _ _ _ _ _ _ _ _ _ _ _ _ cpu_user cpu_system _ < "/proc/$proxy_pid/stat"
        cpu_before=$((cpu_user + cpu_system))
        for task_stat in /proc/$proxy_pid/task/*/stat; do
            task_id=${task_stat%/stat}
            task_id=${task_id##*/}
            task_cpu_before[$task_id]=$(sed 's/^.*) //' "$task_stat" | awk '{ print $12 + $13 }')
        done
    fi
    stack_sampler_pid=
    if [[ ${PN_GDB_EPOLL_OUT:-0} == 1 &&
          $name == tls_idle_after_close_notify && -x /usr/bin/gdb ]]; then
        (
            sleep 1
            gdb -q -batch -p "$proxy_pid" \
                -x "$PN_ROOT/tests/scenarios/smithproxy/capture-epollout.gdb"
        ) > "$WORK_DIR/results/pn-$name-stack.log" 2>&1 &
        stack_sampler_pid=$!
    fi
    set +e
    "$PN" run "$scenario" --trace 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    if [[ -n $stack_sampler_pid ]]; then
        wait "$stack_sampler_pid" || true
    fi
    set -e
    if [[ $name == tls_idle_after_close_notify && -r /proc/$proxy_pid/stat ]]; then
        read -r _ _ _ _ _ _ _ _ _ _ _ _ _ cpu_user cpu_system _ < "/proc/$proxy_pid/stat"
        cpu_after=$((cpu_user + cpu_system))
        cpu_delta=$((cpu_after - cpu_before))
        cpu_hz=$(getconf CLK_TCK)
        printf 'cpu_ticks=%s clk_tck=%s\n' "$cpu_delta" "$cpu_hz" \
            | tee "$WORK_DIR/results/pn-$name-cpu-idle.log"
        for task_stat in /proc/$proxy_pid/task/*/stat; do
            task_id=${task_stat%/stat}
            task_id=${task_id##*/}
            [[ -v task_cpu_before[$task_id] ]] || continue
            task_cpu_after=$(sed 's/^.*) //' "$task_stat" | awk '{ print $12 + $13 }')
            task_cpu_delta=$((task_cpu_after - task_cpu_before[$task_id]))
            ((task_cpu_delta > 0)) || continue
            task_name=$(<"/proc/$proxy_pid/task/$task_id/comm")
            printf 'thread=%s tid=%s cpu_ticks=%s\n' \
                "$task_name" "$task_id" "$task_cpu_delta" \
                | tee -a "$WORK_DIR/results/pn-$name-cpu-idle.log"
        done
        # The scenario contains a two-second idle hold. More than half a CPU
        # second means the supposedly idle connection was actively spinning.
        if ((cpu_delta > cpu_hz / 2)); then
            echo "FAIL: TLS idle connection consumed excessive CPU" | tee -a "$log"
            rc=1
        fi
    fi
    if ((rc == 0)); then
        printf '%s\tPASS\t0\n' "$name" >> "$WORK_DIR/results/pn-summary.tsv"
    else
        printf '%s\tFAIL\t%s\n' "$name" "$rc" >> "$WORK_DIR/results/pn-summary.tsv"
        failed=1
    fi
    ((count += 1))
done < <(
    if [[ -n $SCENARIO ]]; then
        scenario="$PN_ROOT/tests/scenarios/smithproxy/$SCENARIO.pn"
        [[ -f $scenario ]] || { echo "unknown scenario: $SCENARIO" >&2; exit 2; }
        printf '%s\n' "$scenario"
    else
        find "$PN_ROOT/tests/scenarios/smithproxy" -maxdepth 1 -type f -name '*.pn' -print | sort
    fi
)

if ((failed == 0)); then
    echo "PASS: $count Smithproxy ProxyNightmare scenarios"
else
    echo "FAIL: at least one of $count Smithproxy ProxyNightmare scenarios failed" >&2
fi
# Preserve the proxy log outside the root-only runtime directory so a failed
# spin detector can be diagnosed without another privileged reproduction.
if [[ -r $WORK_DIR/data/proxy-console.log ]]; then
    cp "$WORK_DIR/data/proxy-console.log" "$WORK_DIR/results/proxy-console.log"
    chmod 0644 "$WORK_DIR/results/proxy-console.log"
fi
kill -TERM "$LAB_PID"
wait "$LAB_PID" || true
LAB_PID=

if ip netns list | grep -Eq '^(sxr-client|sxr-origin|sxr-data)( |$)'; then
    echo "Smithproxy lab leaked a network namespace" >&2
    exit 1
fi
echo "PASS: Smithproxy lab cleanup"
exit "$failed"
