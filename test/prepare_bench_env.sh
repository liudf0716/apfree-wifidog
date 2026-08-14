#!/bin/sh
# Prepare test environment for TC and AW-BPF benchmark scripts on OpenWrt.
# Usage: ./prepare_bench_env.sh [NUM_EXISTING_RULES]
# Example: ./prepare_bench_env.sh 10
#          ./prepare_bench_env.sh 50
#          ./prepare_bench_env.sh 100

set -eu

DEV="${DEV:-br-lan}"
EXISTING_RULES="${1:-${EXISTING_RULES:-10}}"
BASE_IP_PREFIX="${BASE_IP_PREFIX:-192.168.1.}"
TEST_IP="${TEST_IP:-192.168.1.200}"

echo "=================================================="
echo " Preparing Benchmark Environment on OpenWrt"
echo " Target Device Interface : $DEV"
echo " Pre-existing Rules Count: $EXISTING_RULES"
echo "=================================================="

# 1. Initialize TC HTB Root Qdisc & Class Tree
echo "[1/3] Setting up TC HTB qdisc & class tree on $DEV ($EXISTING_RULES rules)..."
if ! tc qdisc show dev "$DEV" | grep -q 'htb'; then
	tc qdisc add dev "$DEV" root handle 1: htb default 100
	echo "  -> Added HTB root qdisc (1:)"
else
	echo "  -> HTB root qdisc already exists."
fi

if ! tc class show dev "$DEV" | grep -q "class htb 1:1"; then
	tc class add dev "$DEV" parent 1: classid 1:1 htb rate 1000mbit
	echo "  -> Added parent class (1:1)"
fi

if ! tc class show dev "$DEV" | grep -q "class htb 1:100"; then
	tc class add dev "$DEV" parent 1:1 classid 1:100 htb rate 100mbit
	echo "  -> Added default baseline class (1:100)"
fi

# Clean stale TC test class/filter if present
tc filter del dev "$DEV" protocol ip parent 1: prio 220 handle 800::200 u32 >/dev/null 2>&1 || true
tc class del dev "$DEV" classid 1:9200 >/dev/null 2>&1 || true

# Populate pre-existing TC classes and filters
j=1
while [ "$j" -le "$EXISTING_RULES" ]; do
	cid=$((100 + j))
	ip="${BASE_IP_PREFIX}${cid}"
	hnd="800::${cid}"
	if ! tc class show dev "$DEV" | grep -q "class htb 1:${cid}"; then
		tc class add dev "$DEV" parent 1:1 classid "1:${cid}" htb rate 5mbit ceil 5mbit
		tc filter add dev "$DEV" protocol ip parent 1: prio 220 handle "$hnd" u32 match ip dst "${ip}/32" flowid "1:${cid}"
	fi
	j=$((j + 1))
done
echo "  -> Ensured $EXISTING_RULES pre-existing TC classes and filters."

# 2. Initialize AW-BPF Baseline Rules
echo "[2/3] Setting up $EXISTING_RULES AW-BPF baseline rules..."
if command -v aw-bpfctl >/dev/null 2>&1; then
	j=1
	while [ "$j" -le "$EXISTING_RULES" ]; do
		cid=$((100 + j))
		ip="${BASE_IP_PREFIX}${cid}"
		aw-bpfctl ipv4 update "$ip" downrate 5242880 uprate 2097152 >/dev/null 2>&1 || true
		j=$((j + 1))
	done
	# Clean stale BPF test IP if present
	aw-bpfctl ipv4 del "$TEST_IP" >/dev/null 2>&1 || true
	echo "  -> Added $EXISTING_RULES AW-BPF baseline rules."
else
	echo "  [WARNING] aw-bpfctl not found, skipping AW-BPF baseline setup."
fi

# 3. Environment Check Summary
echo "[3/3] Verifying environment setup..."
echo "  - Pre-existing TC Class Count: $(tc class show dev "$DEV" | grep -c 'class htb 1:' || true)"
if command -v aw-bpfctl >/dev/null 2>&1; then
	echo "  - Pre-existing AW-BPF Rule Count: $(aw-bpfctl ipv4 list 2>/dev/null | grep -c '^Key' || true)"
fi

echo "=================================================="
echo " Benchmark Environment Prepared Successfully!"
echo " You can now run:"
echo "   ./bench_auth_tc.sh"
echo "   ./bench_auth_aw_bpf.sh"
echo "=================================================="
