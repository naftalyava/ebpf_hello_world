all: userspace ebpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ebpf.o: vmlinux.h ebpf.c
	clang -O2 -D__TARGET_ARCH_x86 -g -target bpf -c ebpf.c -o ebpf.o

ebpf-go: ebpf.o
	go generate

userspace: ebpf-go
	go build

clean:
	rm -f vmlinux.h ebpf.o main.skel.h main bpf_x86_bpfel.go
	go clean

.PHONY: all clean