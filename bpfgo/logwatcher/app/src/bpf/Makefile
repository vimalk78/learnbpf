

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

logwatcher.bpf.o: logwatcher.bpf.c vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c logwatcher.bpf.c -o  logwatcher.bpf.o

logwatcher.skel.h: logwatcher.bpf.o
	bpftool gen skeleton logwatcher.bpf.o name logwatcher > logwatcher.skel.h

logwatcher: logwatcher.skel.h
	clang logwatcher.c -Wno-unsequenced -lbpf -lelf -o logwatcher
