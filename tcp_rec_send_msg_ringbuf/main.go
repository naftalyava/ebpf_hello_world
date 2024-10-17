package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

func main() {
	pidsFlag := flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	flag.Parse()

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

	if *pidsFlag != "" {
		allowedPidsMap := coll.Maps["allowed_pids"]
		for _, pidStr := range strings.Split(*pidsFlag, ",") {
			pid, err := strconv.ParseUint(strings.TrimSpace(pidStr), 10, 32)
			if err != nil {
				log.Printf("Invalid PID: %s", pidStr)
				continue
			}
			value := uint8(1)
			if err := allowedPidsMap.Put(uint32(pid), &value); err != nil {
				log.Printf("Failed to add PID %d to allowed_pids map: %v", pid, err)
			}
		}
	}

	// Attach eBPF programs
	progSend := coll.Programs["bpf_prog_tcp_sendmsg"]
	if progSend == nil {
		log.Fatal("Failed to find bpf_prog_tcp_sendmsg program")
	}

	progRecv := coll.Programs["bpf_prog_tcp_recvmsg"]
	if progRecv == nil {
		log.Fatal("Failed to find bpf_prog_tcp_recvmsg program")
	}

	sendLink, err := link.Kprobe("tcp_sendmsg", progSend, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer sendLink.Close()

	recvLink, err := link.Kprobe("tcp_recvmsg", progRecv, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer recvLink.Close()

	// Set up ring buffer reader
	rb, err := ringbuf.NewReader(coll.Maps["ip_events"])
	if err != nil {
		log.Fatal(err)
	}
	// We will manually close the ring buffer, so defer is not used here

	// Handle signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	log.Println("TCP monitor running. Press Ctrl+C to exit.")

	var wg sync.WaitGroup
	wg.Add(1)

	// Start a goroutine to read events
	go func() {
		defer wg.Done()
		for {
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// The ring buffer has been closed, exit the goroutine
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			var event IPEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			fmt.Printf("Source: %s:%d -> Destination: %s:%d\n",
				intToIP(event.SrcIP), event.SrcPort,
				intToIP(event.DstIP), event.DstPort)
			if event.PayloadLen > 0 {
				fmt.Printf("Payload (%d bytes): %s\n", event.PayloadLen, string(event.Payload[:event.PayloadLen]))
			}
			fmt.Println("---------------------------")
		}
	}()

	// Wait for a signal
	<-signalCh
	log.Println("Received signal, exiting.")

	// Close the ring buffer reader to unblock the goroutine
	if err := rb.Close(); err != nil {
		log.Printf("Error closing ring buffer reader: %v", err)
	}

	// Wait for the goroutine to finish
	wg.Wait()
}
