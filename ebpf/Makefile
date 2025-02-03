LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS = -I$(PWD)

all: aw-bpf.o update-ipv4_map

# eBPF program compilation
aw-bpf.o: aw-bpf.c
	$(CLANG) -O2 -target bpf -c $< $(BPF_CFLAGS) -o $@

# User space program compilation
update-ipv4_map: update-ipv4_map.c
	$(CC) -O2 -o $@ $< -lbpf

clean:
	rm -f aw-bpf.o update-ipv4_map

# load ebpf program to the kernel by tc in both egress and ingress
load: aw-bpf.o
	sudo tc qdisc add dev eth0 clsact
	sudo tc filter add dev eth0 egress bpf da obj aw-bpf.o sec egress
	sudo tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec ingress

unload:
	sudo tc filter del dev eth0 egress
	sudo tc filter del dev eth0 ingress
	sudo tc qdisc del dev eth0 clsact

status:
	sudo tc filter show dev eth0
	sudo tc qdisc show dev eth0