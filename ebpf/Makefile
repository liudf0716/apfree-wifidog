LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS = -I$(PWD)

all: aw-bpf.o aw-bpfctl

# eBPF program compilation
aw-bpf.o: aw-bpf.c
	$(CLANG) -g -O2 -target bpf -c $< $(BPF_CFLAGS) -o $@

# User space program compilation
aw-bpfctl: aw-bpfctl.c
	$(CC) -O2 -o $@ $< -lbpf -ljson-c -luci

clean:
	rm -f aw-bpf.o aw-bpfctl

# load ebpf program to the kernel by tc in both egress and ingress
load: aw-bpf.o
	sudo tc qdisc add dev eth0 clsact
	sudo tc filter add dev eth0 egress bpf da obj aw-bpf.o sec tc/egress
	sudo tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec tc/ingress

unload:
	sudo tc filter del dev eth0 egress
	sudo tc filter del dev eth0 ingress
	sudo tc qdisc del dev eth0 clsact
	sudo rm -f /sys/fs/bpf/tc/globals/ipv4_map
	sudo rm -f /sys/fs/bpf/tc/globals/ipv6_map
	sudo rm -f /sys/fs/bpf/tc/globals/mac_map

status:
	sudo tc filter show dev eth0
	sudo tc qdisc show dev eth0