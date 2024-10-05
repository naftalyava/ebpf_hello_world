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

// IPEvent represents a TCP connection event with payload
type IPEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint32
	Payload    [2000]byte
}

// intToIP converts a 32-bit integer to a net.IP
func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func printEvent(event IPEvent) {
	fmt.Printf("Source: %s:%d -> Destination: %s:%d\n",
		intToIP(event.SrcIP), event.SrcPort,
		intToIP(event.DstIP), event.DstPort)

	if event.PayloadLen > 0 {
		// Adjust the PayloadLen to exclude trailing zeros
		actualPayloadLen := event.PayloadLen

		// From the end, move backward until we find a non-zero byte
		for actualPayloadLen > 0 && event.Payload[actualPayloadLen-1] == 0 {
			actualPayloadLen--
		}

		if actualPayloadLen == 0 {
			fmt.Println("No payload")
			return
		}
		fmt.Printf("---------------------------\n")
		fmt.Printf("Payload (%d bytes): ", actualPayloadLen)
		// Print each byte as a character if printable, or as a hex value if not
		for i := uint32(0); i < actualPayloadLen; i++ {
			if event.Payload[i] >= 32 && event.Payload[i] <= 126 {
				fmt.Printf("%c", event.Payload[i])
			} else {
				fmt.Printf("\\x%02x", event.Payload[i])
			}
		}
		fmt.Println()
	} else {
		fmt.Println("No payload")
	}
}

func main() {
	log.Println("Starting TCP monitor...")

	// Define a flag for PIDs
	pidsFlag := flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	flag.Parse()

	// Parse the PIDs from the flag
	var pidsToAllow []uint32
	if *pidsFlag != "" {
		pidStrings := strings.Split(*pidsFlag, ",")
		for _, pidStr := range pidStrings {
			pid, err := strconv.ParseUint(strings.TrimSpace(pidStr), 10, 32)
			if err != nil {
				log.Fatalf("Invalid PID: %s", pidStr)
			}
			pidsToAllow = append(pidsToAllow, uint32(pid))
		}
	}

	// Always include the current process PID
	pidsToAllow = append(pidsToAllow, uint32(os.Getpid()))

	// Set the memory lock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF program
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

	// Get the eBPF maps
	ipEventsMap := coll.Maps["ip_events"]
	if ipEventsMap == nil {
		log.Fatal("Failed to find 'ip_events' map")
	}

	allowedPidsMap := coll.Maps["allowed_pids"]
	if allowedPidsMap == nil {
		log.Fatal("Failed to find 'allowed_pids' map")
	}

	log.Println("Found 'ip_events' and 'allowed_pids' maps")

	// Add PIDs to the allowed_pids map
	for _, pid := range pidsToAllow {
		value := uint8(1)
		if err := allowedPidsMap.Put(&pid, &value); err != nil {
			log.Printf("Failed to add PID %d to allowed_pids map: %v", pid, err)
		} else {
			log.Printf("Added PID %d to allowed_pids map", pid)
		}

		// Verify that the PID was actually added
		var checkValue uint8
		if err := allowedPidsMap.Lookup(&pid, &checkValue); err != nil {
			log.Printf("Failed to lookup PID %d in allowed_pids map: %v", pid, err)
		} else {
			log.Printf("Successfully verified PID %d in allowed_pids map", pid)
		}
	}

	// Attach the eBPF programs to the kprobes
	tcpSendmsgProg := coll.Programs["bpf_prog_tcp_sendmsg"]
	if tcpSendmsgProg == nil {
		log.Fatal("Failed to find 'bpf_prog_tcp_sendmsg' program")
	}
	tcpSendmsgLink, err := link.Kprobe("tcp_sendmsg", tcpSendmsgProg, nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_sendmsg' kprobe: %v", err)
	}
	defer tcpSendmsgLink.Close()

	tcpRecvmsgProg := coll.Programs["bpf_prog_tcp_recvmsg"]
	if tcpRecvmsgProg == nil {
		log.Fatal("Failed to find 'bpf_prog_tcp_recvmsg' program")
	}
	tcpRecvmsgLink, err := link.Kprobe("tcp_recvmsg", tcpRecvmsgProg, nil)
	if err != nil {
		log.Fatalf("Failed to attach 'tcp_recvmsg' kprobe: %v", err)
	}
	defer tcpRecvmsgLink.Close()

	log.Println("Attached eBPF programs to kprobes")

	// Channel to handle system signals for graceful exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			var (
				key     uint32
				event   IPEvent
				nextKey uint32
			)

			// Initialize key to zero to start iteration
			key = 0
			eventCount := 0
			for {
				err := ipEventsMap.NextKey(&key, &nextKey)
				if err != nil {
					if err == ebpf.ErrKeyNotExist {
						//log.Println("No more keys in map")
					}
					break
				}

				if err := ipEventsMap.Lookup(&nextKey, &event); err != nil {
					log.Printf("Failed to lookup event: %v", err)
				} else {
					//log.Printf("Found event with key %d", nextKey)

					printEvent(event)

					// Delete the event from the map after processing
					if err := ipEventsMap.Delete(&nextKey); err != nil {
						log.Printf("Failed to delete event: %v", err)
					}

					eventCount++
				}

				key = nextKey
			}
			//log.Printf("Processed %d events", eventCount)

			time.Sleep(1 * time.Second)
		}
	}()

	log.Println("Waiting for events. Press Ctrl+C to exit.")
	<-sigCh
	fmt.Println("Exiting...")
}
