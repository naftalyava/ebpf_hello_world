package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// IPEvent represents a TCP connection event
type IPEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// intToIP converts a 32-bit integer to a net.IP
func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	log.Println("Starting TCP monitor...")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	log.Println("eBPF program loaded successfully")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	log.Println("eBPF collection created successfully")

	ipEventsMap, ok := coll.Maps["ip_events"]
	if !ok {
		log.Fatal("Failed to find 'ip_events' map")
	}

	log.Println("Found 'ip_events' map")

	// Attach the eBPF programs to the kprobes
	tcpSendmsgProg, ok := coll.Programs["bpf_prog_tcp_sendmsg"]
	if !ok {
		log.Fatal("Failed to find 'bpf_prog_tcp_sendmsg' program")
	}

	tcpRecvmsgProg, ok := coll.Programs["bpf_prog_tcp_recvmsg"]
	if !ok {
		log.Fatal("Failed to find 'bpf_prog_tcp_recvmsg' program")
	}

	renameat2Prog, ok := coll.Programs["probe_renameat2"]
	if !ok {
		log.Fatal("Failed to find 'probe_renameat2' program")
	}

	// Attach the programs to the respective kprobes
	tcpSendmsgLink, err := link.Kprobe("tcp_sendmsg", tcpSendmsgProg, nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_sendmsg' kprobe: %v", err)
	}
	defer tcpSendmsgLink.Close()

	tcpRecvmsgLink, err := link.Kprobe("tcp_recvmsg", tcpRecvmsgProg, nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_recvmsg' kprobe: %v", err)
	}
	defer tcpRecvmsgLink.Close()

	renameat2Link, err := link.Kprobe("do_renameat2", renameat2Prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach 'do_renameat2' kprobe: %v", err)
	}
	defer renameat2Link.Close()

	log.Println("Attached eBPF programs to kprobes")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			log.Println("Checking for events...")
			var (
				key     uint32
				event   IPEvent
				nextKey uint32
			)

			// Initialize key to zero to start iteration
			key = 0

			for {
				err := ipEventsMap.NextKey(&key, &nextKey)
				if err != nil {
					if err == ebpf.ErrKeyNotExist {
						log.Println("No more entries in map")
					}
					break
				}

				if err := ipEventsMap.Lookup(&nextKey, &event); err != nil {
					log.Printf("Failed to lookup event: %v", err)
				} else {
					fmt.Printf("Source: %s:%d -> Destination: %s:%d\n",
						intToIP(event.SrcIP), event.SrcPort,
						intToIP(event.DstIP), event.DstPort)

					if err := ipEventsMap.Delete(&nextKey); err != nil {
						log.Printf("Failed to delete event: %v", err)
					}
				}

				key = nextKey
			}

			time.Sleep(1 * time.Second)
		}
	}()

	log.Println("Waiting for events. Press Ctrl+C to exit.")
	<-sigCh
	fmt.Println("Exiting...")
}
