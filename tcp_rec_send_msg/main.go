package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type IPEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint32
	Payload    [4000]byte
}

func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func printEvent(event IPEvent) {
	fmt.Printf("Source: %s:%d -> Destination: %s:%d\n",
		intToIP(event.SrcIP), event.SrcPort,
		intToIP(event.DstIP), event.DstPort)

	if event.PayloadLen > 0 {
		fmt.Printf("Payload (%d bytes): %s\n", event.PayloadLen, string(event.Payload[:event.PayloadLen]))
	} else {
		fmt.Println("No payload")
	}
	fmt.Println("---------------------------")
}

func main() {
	pidsFlag := flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	flag.Parse()

	var pidsToAllow []uint32
	if *pidsFlag != "" {
		for _, pidStr := range strings.Split(*pidsFlag, ",") {
			pid, err := strconv.ParseUint(strings.TrimSpace(pidStr), 10, 32)
			if err != nil {
				log.Fatalf("Invalid PID: %s", pidStr)
			}
			pidsToAllow = append(pidsToAllow, uint32(pid))
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	ipEventsMap := coll.Maps["ip_events"]
	allowedPidsMap := coll.Maps["allowed_pids"]
	if ipEventsMap == nil || allowedPidsMap == nil {
		log.Fatal("Failed to find required maps")
	}

	for _, pid := range pidsToAllow {
		value := uint8(1)
		if err := allowedPidsMap.Put(&pid, &value); err != nil {
			log.Printf("Failed to add PID %d to allowed_pids map: %v", pid, err)
		}
	}

	tcpSendmsgLink, err := link.Kprobe("tcp_sendmsg", coll.Programs["bpf_prog_tcp_sendmsg"], nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_sendmsg' kprobe: %v", err)
	}
	defer tcpSendmsgLink.Close()

	tcpRecvmsgLink, err := link.Kprobe("tcp_recvmsg", coll.Programs["bpf_prog_tcp_recvmsg"], nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_recvmsg' kprobe: %v", err)
	}
	defer tcpRecvmsgLink.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			var event IPEvent
			var nextKey uint32

			err := ipEventsMap.NextKey(nil, &nextKey)
			if err == nil {
				if err := ipEventsMap.Lookup(&nextKey, &event); err == nil {
					printEvent(event)
					ipEventsMap.Delete(&nextKey)
				}
			}

			time.Sleep(time.Second)
		}
	}()

	log.Println("TCP monitor running. Press Ctrl+C to exit.")
	<-sig
	fmt.Println("Exiting...")
}
