LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS = -I$(PWD)

# xDPI功能控制 (默认启用)
# 设置 ENABLE_XDPI_FEATURE=0 来禁用xDPI功能
ENABLE_XDPI_FEATURE ?= 1

ifeq ($(ENABLE_XDPI_FEATURE),1)
    BPF_CFLAGS += -DENABLE_XDPI_FEATURE
    $(info xDPI feature enabled)
else
    $(info xDPI feature disabled)
endif

# 检查是否安装了 libcurl
CURL_LIBS := $(shell pkg-config --libs libcurl 2>/dev/null)
ifneq ($(CURL_LIBS),)
    CFLAGS += -DHAVE_LIBCURL $(shell pkg-config --cflags libcurl)
    LDFLAGS += $(CURL_LIBS)
else
    CFLAGS += -DUSE_SYSTEM_CURL
endif

obj-m := xdpi-bpf.o  

all: aw-bpf.o dns-bpf.o aw-bpfctl event_daemon dns-monitor
	@if [ -d /lib/modules/$(shell uname -r)/build ]; then \
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules; \
	else \
		echo "Kernel build directory not found"; \
	fi

# eBPF program compilation
aw-bpf.o: aw-bpf.c
	$(CLANG) -g -O2 -target bpf -c $< $(BPF_CFLAGS) -o $@

# DNS eBPF program compilation
dns-bpf.o: dns-bpf.c
	$(CLANG) -g -O2 -target bpf -c $< $(BPF_CFLAGS) -o $@

# User space program compilation
aw-bpfctl: aw-bpfctl.c
	$(CC) -O2 $(CFLAGS) -o $@ $< -lbpf -ljson-c -luci $(LDFLAGS)

# Event daemon compilation
event_daemon: event_daemon.c
	$(CC) -O2 $(CFLAGS) -o $@ $< -lbpf -lelf -lpthread -luci $(LDFLAGS)

# DNS monitor user space program compilation
dns-monitor: dns-monitor.c
	$(CC) -O2 $(CFLAGS) -o $@ $< -lbpf $(LDFLAGS)

# Test program for xdpi-bpf kernel function
test_xdpi: test_xdpi-bpf.c
	$(CC) -o $@ $< -Wall -Werror -O2
	@echo "Running test_xdpi:"
	@./test_xdpi

clean:
	rm -f aw-bpf.o dns-bpf.o aw-bpfctl event_daemon dns-monitor test_xdpi
	@if [ -d /lib/modules/$(shell uname -r)/build ]; then \
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean; \
	else \
		echo "Kernel build directory not found"; \
	fi

# load ebpf program to the kernel by tc in both egress and ingress
load: aw-bpf.o
	sudo tc qdisc add dev eth0 clsact
	sudo tc filter add dev eth0 egress bpf da obj aw-bpf.o sec tc/egress
	sudo tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec tc/ingress

# load DNS monitor eBPF program (only ingress for DNS responses)
load-dns: dns-bpf.o
	sudo tc qdisc add dev eth0 clsact 2>/dev/null || true
	sudo tc filter add dev eth0 ingress bpf da obj dns-bpf.o sec tc/dns/ingress
	@echo "DNS response monitor loaded on ingress. Check ring buffer events in user space program."

# load xdpi classifier using tc
load-xdpi: aw-bpf.o xdpi-bpf.ko
	sudo insmod xdpi-bpf.ko || true
	sudo tc qdisc add dev eth0 clsact 2>/dev/null || true
	sudo tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec classifier/xdpi
	@echo "Check trace logs with: sudo cat /sys/kernel/debug/tracing/trace_pipe"

unload:
	sudo tc filter del dev eth0 egress
	sudo tc filter del dev eth0 ingress
	sudo tc qdisc del dev eth0 clsact
	sudo rm -f /sys/fs/bpf/tc/globals/ipv4_map
	sudo rm -f /sys/fs/bpf/tc/globals/ipv6_map
	sudo rm -f /sys/fs/bpf/tc/globals/mac_map

unload-dns:
	sudo tc filter del dev eth0 ingress 2>/dev/null || true
	sudo tc qdisc del dev eth0 clsact 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/dns_ringbuf 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/dns_stats_map 2>/dev/null || true
	@echo "DNS response monitor unloaded."

unload-xdpi:
	sudo tc filter del dev eth0 ingress 2>/dev/null || true
	sudo tc qdisc del dev eth0 clsact 2>/dev/null || true
	sudo rmmod xdpi-bpf 2>/dev/null || true

status:
	sudo tc filter show dev eth0
	sudo tc qdisc show dev eth0

# Simple target to run just the test
test: test_xdpi
