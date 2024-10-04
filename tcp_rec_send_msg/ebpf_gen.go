package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 bpf main.bpf.c -- -I../headers
