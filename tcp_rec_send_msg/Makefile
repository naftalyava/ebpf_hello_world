all: userspace main.bpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

main.bpf.o: vmlinux.h main.bpf.c
	clang -O2 -D__TARGET_ARCH_x86 -g -target bpf -c main.bpf.c -o main.bpf.o

ebpf-go: main.bpf.o
	go generate

userspace: ebpf-go
	go build

clean:
	rm -f vmlinux.h main.bpf.o main.skel.h main bpf_x86_bpfel.go
	go clean

.PHONY: all clean