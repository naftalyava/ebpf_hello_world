package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// Path to the compiled eBPF object file
	ebpfObjFile = "malloc_free_tracer.o"
)

// AllocInfo mirrors the struct in the eBPF program
type AllocInfo struct {
	Size    uint64
	StackID int32
}

func main() {
	// Parse command-line arguments
	pid := flag.Int("pid", 0, "PID of the target process")
	outputFile := flag.String("output", "leaks.txt", "File to write final results")
	flag.Parse()

	if *pid == 0 {
		log.Fatal("Please specify a PID using -pid")
	}

	// Allow the current process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load eBPF program
	objs := struct {
		MallocEnter *ebpf.Program `ebpf:"malloc_enter"`
		MallocExit  *ebpf.Program `ebpf:"malloc_exit"`
		FreeEnter   *ebpf.Program `ebpf:"free_enter"`
		Allocs      *ebpf.Map     `ebpf:"allocs"`
		StackTraces *ebpf.Map     `ebpf:"stack_traces"`
	}{}

	if err := loadEBPFObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.MallocEnter.Close()
	defer objs.MallocExit.Close()
	defer objs.FreeEnter.Close()
	defer objs.Allocs.Close()
	defer objs.StackTraces.Close()

	// Attach uprobes to malloc and free
	exePath := fmt.Sprintf("/proc/%d/exe", *pid)

	// Open the target executable
	executable, err := link.OpenExecutable(exePath)
	if err != nil {
		log.Fatalf("Failed to open executable: %v", err)
	}

	// Attach uprobe to malloc
	mallocUprobe, err := executable.Uprobe("malloc", objs.MallocEnter, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach malloc uprobe: %v", err)
	}
	defer mallocUprobe.Close()

	// Attach uretprobe to malloc
	mallocRetUprobe, err := executable.Uretprobe("malloc", objs.MallocExit, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach malloc uretprobe: %v", err)
	}
	defer mallocRetUprobe.Close()

	// Attach uprobe to free
	freeUprobe, err := executable.Uprobe("free", objs.FreeEnter, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach free uprobe: %v", err)
	}
	defer freeUprobe.Close()

	log.Printf("Tracing malloc and free of process %d... Press Ctrl+C to stop.", *pid)

	// Handle signals for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("Stopping trace and collecting results...")

	// Collect leaks
	leaks, err := collectLeaks(objs.Allocs, objs.StackTraces)
	if err != nil {
		log.Fatalf("Failed to collect leaks: %v", err)
	}

	// Write final results to file
	if err := writeResults(*outputFile, leaks); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}

	log.Printf("Leak detection complete. Results written to %s", *outputFile)
}

// collectLeaks retrieves allocation information from eBPF maps
func collectLeaks(allocsMap *ebpf.Map, stackTracesMap *ebpf.Map) (map[uint64]AllocInfo, error) {
	leaks := make(map[uint64]AllocInfo)

	it := allocsMap.Iterate()
	var addr uint64
	var info AllocInfo
	for it.Next(&addr, &info) {
		leaks[addr] = info
		// Print intermediate data
		fmt.Printf("Leak detected at address: 0x%x, size: %d bytes\n", addr, info.Size)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return leaks, nil
}

// writeResults writes the leak information to the specified file
func writeResults(filename string, leaks map[uint64]AllocInfo) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for addr, info := range leaks {
		fmt.Fprintf(writer, "Leak at address: 0x%x, size: %d bytes\n", addr, info.Size)
		fmt.Fprintf(writer, "Stack trace:\n")
		stack, err := getStackTrace(info.StackID, info.Size)
		if err != nil {
			fmt.Fprintf(writer, "  [Failed to retrieve stack trace: %v]\n", err)
		} else {
			for _, frame := range stack {
				fmt.Fprintf(writer, "  %s\n", frame)
			}
		}
		fmt.Fprintln(writer)
	}
	return writer.Flush()
}

// getStackTrace resolves stack IDs to symbols
func getStackTrace(stackID int32, size uint64) ([]string, error) {
	// This function should resolve the stack trace using symbols from the binary.
	// For simplicity, we'll return a placeholder here.
	return []string{"[Stack trace resolution not implemented]"}, nil
}

// loadEBPFObjects loads the compiled eBPF object file
func loadEBPFObjects(objs interface{}, opts *ebpf.CollectionOptions) error {
	f, err := os.Open(ebpfObjFile)
	if err != nil {
		return err
	}
	defer f.Close()
	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(objs, opts)
}
