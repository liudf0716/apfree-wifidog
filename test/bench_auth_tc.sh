#!/bin/sh
# Benchmark TC class/filter add/delete operations for an authenticated IP.
# Assumptions: DEV already has an HTB qdisc, and CLASS_PARENT is an existing
# parent class. The script uses only TEST_CLASS/TEST_HANDLE and preserves the
# existing TC tree.

set -eu

DEV="${DEV:-br-lan}"
TEST_IP="${TEST_IP:-192.168.1.200}"
RATE="${RATE:-5mbit}"
LOOPS="${LOOPS:-100}"

CLASS_PARENT="${CLASS_PARENT:-1:1}"
BASE_CLASS="${BASE_CLASS:-1:101}"
FILTER_PARENT="${FILTER_PARENT:-1:}"
TEST_CLASS="${TEST_CLASS:-1:9200}"
TEST_HANDLE="${TEST_HANDLE:-800::200}"
FILTER_PRIO="${FILTER_PRIO:-220}"

TMP_DIR="${TMPDIR:-/tmp}/bench-auth-tc.$$"
mkdir -p "$TMP_DIR"
CREATED=0

cleanup()
{
	if [ "$CREATED" -eq 1 ]; then
		tc filter del dev "$DEV" protocol ip parent "$FILTER_PARENT" \
			prio "$FILTER_PRIO" handle "$TEST_HANDLE" u32 >/dev/null 2>&1 || true
		tc class del dev "$DEV" classid "$TEST_CLASS" >/dev/null 2>&1 || true
	fi
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

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

check_environment()
{
	command -v tc >/dev/null 2>&1 || {
		echo "ERROR: tc not found" >&2
		exit 1
	}

	if ! tc qdisc show dev "$DEV" | grep -q 'htb'; then
		echo "ERROR: no HTB qdisc found on $DEV" >&2
		tc qdisc show dev "$DEV" >&2
		exit 1
	fi

	if ! tc class show dev "$DEV" | grep -q "class htb $CLASS_PARENT"; then
		echo "ERROR: parent class not found: $CLASS_PARENT" >&2
		tc class show dev "$DEV" >&2
		exit 1
	fi

	if ! tc class show dev "$DEV" | grep -q "class htb $BASE_CLASS"; then
		echo "ERROR: baseline user class not found: $BASE_CLASS" >&2
		tc class show dev "$DEV" >&2
		exit 1
	fi

	if tc class show dev "$DEV" | grep -q "class htb $TEST_CLASS"; then
		echo "ERROR: TEST_CLASS is already in use: $TEST_CLASS" >&2
		exit 1
	fi
}

add_rule()
{
	tc class add dev "$DEV" parent "$CLASS_PARENT" classid "$TEST_CLASS" \
		htb rate "$RATE" ceil "$RATE"
	tc filter add dev "$DEV" protocol ip parent "$FILTER_PARENT" \
		prio "$FILTER_PRIO" handle "$TEST_HANDLE" u32 \
		match ip dst "$TEST_IP/32" flowid "$TEST_CLASS"
	CREATED=1
}

remove_rule()
{
	tc filter del dev "$DEV" protocol ip parent "$FILTER_PARENT" \
		prio "$FILTER_PRIO" handle "$TEST_HANDLE" u32
	tc class del dev "$DEV" classid "$TEST_CLASS"
	CREATED=0
}

measure_add()
{
	start=$(get_now_ns)
	add_rule
	end=$(get_now_ns)
	echo $((end - start))
}

measure_remove()
{
	start=$(get_now_ns)
	remove_rule
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

check_environment

echo "TC auth QoS benchmark"
echo "  device     : $DEV"
echo "  baseline class: $BASE_CLASS"
echo "  test IP    : $TEST_IP"
echo "  rate       : $RATE"
echo "  class      : $TEST_CLASS"
echo "  handle     : $TEST_HANDLE"
echo "  loops      : $LOOPS"

i=1
while [ "$i" -le "$LOOPS" ]; do
	add_ns=$(measure_add)
	remove_ns=$(measure_remove)

	echo "$add_ns" >> "$TMP_DIR/add"
	echo "$remove_ns" >> "$TMP_DIR/remove"

	# The parent class and all pre-existing rules remain untouched.
	if ! tc class show dev "$DEV" | grep -q "class htb $CLASS_PARENT"; then
		echo "ERROR: parent class disappeared at iteration $i" >&2
		exit 1
	fi

	echo "iteration=$i add_ns=$add_ns remove_ns=$remove_ns"
	i=$((i + 1))
done

echo
echo "TC summary:"
summary add "$TMP_DIR/add"
summary remove "$TMP_DIR/remove"
