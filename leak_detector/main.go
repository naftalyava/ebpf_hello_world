// main.go
package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// Path to the compiled eBPF object file
	ebpfObjFile   = "ebpf.o"
	maxStackDepth = 64
)

// AllocInfo mirrors the struct in the eBPF program
type AllocInfo struct {
	Size    uint64
	StackID int32
	Padding uint32 // Added padding to match eBPF struct size
}

// Stack trace key type
type StackTrace [maxStackDepth]uint64

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

	// Get the path to libc used by the target process
	libcPath, err := getLibcPath(*pid)
	if err != nil {
		log.Fatalf("Failed to get libc path: %v", err)
	}
	log.Printf("Using libc path: %s", libcPath)

	// Open the libc library
	executable, err := link.OpenExecutable(libcPath)
	if err != nil {
		log.Fatalf("Failed to open libc: %v", err)
	}

	// Attach uprobe to malloc in libc
	mallocUprobe, err := executable.Uprobe("malloc", objs.MallocEnter, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach malloc uprobe: %v", err)
	}
	defer mallocUprobe.Close()
	log.Println("Attached malloc uprobe.")

	// Attach uretprobe to malloc in libc
	mallocRetUprobe, err := executable.Uretprobe("malloc", objs.MallocExit, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach malloc uretprobe: %v", err)
	}
	defer mallocRetUprobe.Close()
	log.Println("Attached malloc uretprobe.")

	// Attach uprobe to free in libc
	freeUprobe, err := executable.Uprobe("free", objs.FreeEnter, &link.UprobeOptions{
		PID: *pid,
	})
	if err != nil {
		log.Fatalf("Failed to attach free uprobe: %v", err)
	}
	defer freeUprobe.Close()
	log.Println("Attached free uprobe.")

	log.Printf("Tracing malloc and free of process %d... Press Ctrl+C to stop.", *pid)

	// Set up signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Start a ticker to periodically collect and display leaks
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				// Collect and display leaks
				leaks, err := collectLeaks(objs.Allocs)
				if err != nil {
					log.Printf("Failed to collect leaks: %v", err)
					continue
				}
				if len(leaks) == 0 {
					log.Println("No leaks detected.")
				} else {
					log.Printf("Current possible leaks (%d):", len(leaks))
					for addr, info := range leaks {
						log.Printf("Possible leak at address: 0x%x, size: %d bytes, StackID: %d", addr, info.Size, info.StackID)
						// Optionally resolve stack trace here
					}
				}
			case <-sigs:
				done <- true
				return
			}
		}
	}()

	// Wait for signal to exit
	<-done

	log.Println("Stopping trace and collecting final results...")

	// Collect leaks one last time
	leaks, err := collectLeaks(objs.Allocs)
	if err != nil {
		log.Fatalf("Failed to collect leaks: %v", err)
	}

	// Write final results to file
	if err := writeResults(*outputFile, leaks, objs.StackTraces, *pid); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}

	log.Printf("Leak detection complete. Results written to %s", *outputFile)
}

// getLibcPath finds the path to libc used by the target process
func getLibcPath(pid int) (string, error) {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "/libc-") || strings.Contains(line, "/libc.so") {
			// Extract the path
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				path := fields[len(fields)-1]
				// Return the first occurrence
				return path, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("libc not found in process maps")
}

// collectLeaks retrieves allocation information from eBPF maps
func collectLeaks(allocsMap *ebpf.Map) (map[uint64]AllocInfo, error) {
	leaks := make(map[uint64]AllocInfo)

	it := allocsMap.Iterate()
	var addr uint64
	var info AllocInfo
	for it.Next(&addr, &info) {
		leaks[addr] = info
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return leaks, nil
}

// writeResults writes the leak information to the specified file
func writeResults(filename string, leaks map[uint64]AllocInfo, stackTracesMap *ebpf.Map, pid int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for addr, info := range leaks {
		fmt.Fprintf(writer, "Leak at address: 0x%x, size: %d bytes\n", addr, info.Size)
		fmt.Fprintf(writer, "Stack trace:\n")
		stack, err := getStackTrace(info.StackID, stackTracesMap, pid)
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
func getStackTrace(stackID int32, stackTracesMap *ebpf.Map, pid int) ([]string, error) {
	if stackID < 0 {
		return nil, fmt.Errorf("invalid stack ID: %d", stackID)
	}

	var stackTrace StackTrace
	err := stackTracesMap.Lookup(stackID, &stackTrace)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup stack trace: %v", err)
	}

	// Read /proc/<pid>/maps to get the memory mappings
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	symResolver, err := NewSymbolResolver(mapsFile)
	if err != nil {
		return nil, err
	}

	frames := []string{}
	for _, pc := range stackTrace {
		if pc == 0 {
			continue
		}
		sym, err := symResolver.Resolve(pc)
		if err != nil {
			frames = append(frames, fmt.Sprintf("0x%x [unknown]", pc))
		} else {
			frames = append(frames, fmt.Sprintf("0x%x %s", pc, sym))
		}
	}

	return frames, nil
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

// SymbolResolver resolves program counters to symbols
type SymbolResolver struct {
	mappings []procMapEntry
}

type procMapEntry struct {
	start, end uint64
	offset     uint64
	path       string
	symbols    map[uint64]string
}

func NewSymbolResolver(mapsFile string) (*SymbolResolver, error) {
	f, err := os.Open(mapsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	resolver := &SymbolResolver{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		addresses := strings.Split(fields[0], "-")
		if len(addresses) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addresses[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			continue
		}
		offset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			continue
		}
		path := fields[5]
		if strings.HasPrefix(path, "/") && strings.Contains(fields[1], "x") {
			// Load symbols from the binary
			symbols, err := loadSymbols(path)
			if err != nil {
				continue
			}
			resolver.mappings = append(resolver.mappings, procMapEntry{
				start:   start,
				end:     end,
				offset:  offset,
				path:    path,
				symbols: symbols,
			})
		}
	}
	return resolver, nil
}

func demangleSymbol(sym string) string {
	cmd := exec.Command("c++filt", sym)
	output, err := cmd.Output()
	if err != nil {
		return sym // Return the original symbol if demangling fails
	}
	return strings.TrimSpace(string(output))
}

func (r *SymbolResolver) Resolve(pc uint64) (string, error) {
	for _, m := range r.mappings {
		if pc >= m.start && pc < m.end {
			// Adjust pc to file offset
			fileOffset := pc - m.start + m.offset
			// Find the closest symbol
			var closestAddr uint64
			var closestSym string
			for addr, sym := range m.symbols {
				if addr <= fileOffset && addr >= closestAddr {
					closestAddr = addr
					closestSym = sym
				}
			}
			if closestSym != "" {
				// Demangle the symbol
				demangledSym := demangleSymbol(closestSym)
				return fmt.Sprintf("%s (%s)", demangledSym, m.path), nil
			}
		}
	}
	return "", fmt.Errorf("symbol not found for address 0x%x", pc)
}

func loadSymbols(path string) (map[uint64]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Parse the ELF file
	symbols := make(map[uint64]string)
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, err
	}

	// Collect symbols from the symbol tables
	collectSymbols := func(syms []elf.Symbol) {
		for _, sym := range syms {
			if sym.Value == 0 || sym.Size == 0 {
				continue
			}
			symbols[sym.Value] = sym.Name
		}
	}

	// Read the symbols from the symbol table
	syms, err := elfFile.Symbols()
	if err == nil {
		collectSymbols(syms)
	}

	// Read the symbols from the dynamic symbol table
	dynSyms, err := elfFile.DynamicSymbols()
	if err == nil {
		collectSymbols(dynSyms)
	}

	return symbols, nil
}
