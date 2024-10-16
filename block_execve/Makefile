all: main

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

main.bpf.o: vmlinux.h main.bpf.c
	clang -O2 -D__TARGET_ARCH_x86 -g -target bpf -c main.bpf.c -o main.bpf.o

main.skel.h: main.bpf.o
	sudo bpftool gen skeleton main.bpf.o > main.skel.h

main: main.skel.h main.c
	gcc -o main main.c -lbpf

clean:
	rm -f vmlinux.h main.bpf.o main.skel.h main

.PHONY: all clean
