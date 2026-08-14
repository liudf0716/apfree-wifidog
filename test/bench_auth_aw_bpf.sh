#!/bin/sh
# Benchmark per-IP add/delete operations used by the AW-BPF auth QoS path.
# This script does not modify BASE_IP. TEST_IP must not already exist.

set -eu

AW_BPFCTL="${AW_BPFCTL:-aw-bpfctl}"
BASE_IP="${BASE_IP:-192.168.1.101}"
TEST_IP="${TEST_IP:-192.168.1.200}"
DOWN_BPS="${DOWN_BPS:-5242880}"
UP_BPS="${UP_BPS:-2097152}"
LOOPS="${LOOPS:-100}"

TMP_DIR="${TMPDIR:-/tmp}/bench-auth-aw-bpf.$$"
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

list_ipv4()
{
	"$AW_BPFCTL" ipv4 list 2>/dev/null
}

require_baseline()
{
	if ! list_ipv4 | grep -q "^Key (IPv4): $BASE_IP$"; then
		echo "ERROR: baseline AW-BPF rule not found: $BASE_IP" >&2
		exit 1
	fi
}

require_test_absent()
{
	if list_ipv4 | grep -q "^Key (IPv4): $TEST_IP$"; then
		echo "ERROR: TEST_IP already exists; refusing to delete it: $TEST_IP" >&2
		exit 1
	fi
}

get_now_ns()
{
	ns=$(date +%s%N 2>/dev/null || true)
	if echo "$ns" | grep -qE '^[0-9]{11,}$'; then
		echo "$ns"
		return 0
	fi

	if [ -f /proc/timer_list ]; then
		ns=$(awk '/now at/ {print $3; exit}' /proc/timer_list 2>/dev/null || true)
		if echo "$ns" | grep -qE '^[0-9]+$'; then
			echo "$ns"
			return 0
		fi
	fi

	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import time; print(time.time_ns())' 2>/dev/null && return 0
	fi

	if command -v perl >/dev/null 2>&1; then
		perl -e 'use Time::HiRes qw(time); print int(time() * 1000000000)' 2>/dev/null && return 0
	fi

	if [ -f /proc/uptime ]; then
		awk '{printf "%.0f\n", $1 * 1000000000}' /proc/uptime 2>/dev/null && return 0
	fi

	echo "$(( $(date +%s) * 1000000000 ))"
}

measure_apply()
{
	start=$(get_now_ns)
	"$AW_BPFCTL" ipv4 update "$TEST_IP" \
		downrate "$DOWN_BPS" uprate "$UP_BPS" >/dev/null
	end=$(get_now_ns)
	echo $((end - start))
}

measure_remove()
{
	start=$(get_now_ns)
	"$AW_BPFCTL" ipv4 del "$TEST_IP" >/dev/null
	end=$(get_now_ns)
	echo $((end - start))
}

summary()
{
	name="$1"
	file="$2"
	awk -v name="$name" '
	{
		if (min == 0 || $1 < min) min = $1
		if ($1 > max) max = $1
		sum += $1
		count++
	}
	END {
		if (count > 0)
			printf "%s,count=%d,min_ns=%d,avg_ns=%.0f,max_ns=%d,avg_ms=%.3f\n",
			       name, count, min, sum / count, max, (sum / count) / 1000000
	}' "$file"
}

command -v "$AW_BPFCTL" >/dev/null 2>&1 || {
	echo "ERROR: aw-bpfctl not found: $AW_BPFCTL" >&2
	exit 1
}

require_baseline
require_test_absent

echo "AW-BPF auth QoS benchmark"
echo "  baseline IP: $BASE_IP"
echo "  test IP    : $TEST_IP"
echo "  downrate   : $DOWN_BPS bps"
echo "  uprate     : $UP_BPS bps"
echo "  loops      : $LOOPS"

i=1
while [ "$i" -le "$LOOPS" ]; do
	apply_ns=$(measure_apply)
	remove_ns=$(measure_remove)

	echo "$apply_ns" >> "$TMP_DIR/apply"
	echo "$remove_ns" >> "$TMP_DIR/remove"

	# The pre-existing authenticated user's rule must survive every iteration.
	require_baseline
	echo "iteration=$i apply_ns=$apply_ns remove_ns=$remove_ns"
	i=$((i + 1))
done

echo
echo "AW-BPF summary:"
summary apply "$TMP_DIR/apply"
summary remove "$TMP_DIR/remove"

