//go:build ignore

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	iterations := flag.Int("iterations", 5, "Number of iterations for client send operations")
	port := flag.Int("port", 8080, "Port number for the server to listen on")
	flag.Parse()

	pid := os.Getpid()
	log.Printf("Test program started. PID: %d", pid)

	var wg sync.WaitGroup
	wg.Add(1)
	go startTCPServer(*port, &wg)

	time.Sleep(time.Second)
	startTCPClientIovec(*iterations, *port)
	wg.Wait()

	log.Println("Test program completed.")
}

func startTCPServer(port int, wg *sync.WaitGroup) {
	defer wg.Done()

	addr := fmt.Sprintf("localhost:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server: Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("Server: Listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Server: Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	log.Printf("Server: Connection established with %s", clientAddr)

	buffer := make([]byte, 4096)
	for {
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Server: Error reading from %s: %v", clientAddr, err)
			}
			break
		}

		_, err = conn.Write(buffer[:bytesRead])
		if err != nil {
			log.Printf("Server: Error writing to %s: %v", clientAddr, err)
			break
		}

		receivedData := string(buffer[:bytesRead])
		log.Printf("Server: Received and echoed back %d bytes from %s: %s", bytesRead, clientAddr, receivedData)
	}
	log.Printf("Server: Connection closed with %s", clientAddr)
}

func startTCPClientIovec(iterations int, port int) {
	addr := fmt.Sprintf("localhost:%d", port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Client: Failed to connect to %s: %v", addr, err)
		return
	}
	defer conn.Close()

	log.Printf("Client: Connected to %s", addr)

	fd, err := getFDFromConn(conn)
	if err != nil {
		log.Fatalf("Client: Failed to get file descriptor: %v", err)
		return
	}

	for i := 0; i < iterations; i++ {
		// Prepare the buffers to send
		buf1 := []byte(fmt.Sprintf("Ping %d: Buffer 1 at %s\n", i, time.Now().Format(time.RFC3339)))
		buf2 := []byte(fmt.Sprintf("Ping %d: Buffer 2 at %s\n", i, time.Now().Format(time.RFC3339)))
		buf3 := []byte(fmt.Sprintf("Ping %d: Buffer 3 at %s\n", i, time.Now().Format(time.RFC3339)))

		// Create the iovec structures
		iov := []unix.Iovec{
			{Base: &buf1[0], Len: uint64(len(buf1))},
			{Base: &buf2[0], Len: uint64(len(buf2))},
			{Base: &buf3[0], Len: uint64(len(buf3))},
		}

		// Write using writev
		bytesSent, err := unix.Writev(fd, iov)
		if err != nil {
			log.Printf("Client: Failed to writev on iteration %d: %v", i, err)
			return
		}
		log.Printf("Client: Iteration %d: Sent %d bytes using writev", i, bytesSent)

		// Read the echo response
		buffer := make([]byte, 4096)
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Client: Failed to read on iteration %d: %v", i, err)
			return
		}
		echoedData := string(buffer[:bytesRead])
		log.Printf("Client: Iteration %d: Received %d bytes: %s", i, bytesRead, echoedData)

		time.Sleep(1 * time.Second)
	}
	log.Println("Client: Completed all iterations")
}

// getFDFromConn retrieves the file descriptor from a net.Conn
func getFDFromConn(conn net.Conn) (int, error) {
	sysConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return -1, fmt.Errorf("failed to get raw connection interface")
	}

	var fd int
	var err error
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("failed to get raw conn: %v", err)
	}

	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, fmt.Errorf("failed to get fd: %v", err)
	}

	return fd, nil
}
