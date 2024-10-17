package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

func main() {
	iterations := flag.Int("iterations", 5, "Number of iterations for client send operations")
	port := flag.Int("port", 8080, "Port number for the server to listen on")
	flag.Parse()

	pid := os.Getpid()
	log.Printf("Test program started. PID: %d", pid)

	// Start the TCP server in a separate goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go startTCPServer(*port, &wg)

	// Give the server a moment to start
	time.Sleep(time.Second)

	// Start the TCP client
	startTCPClient(*iterations, *port)

	// Wait for the server to finish
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

	buffer := make([]byte, 1024)
	for {
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Server: Error reading from %s: %v", clientAddr, err)
			}
			break
		}

		// Echo back the received data
		_, err = conn.Write(buffer[:bytesRead])
		if err != nil {
			log.Printf("Server: Error writing to %s: %v", clientAddr, err)
			break
		}

		// Log the received data
		receivedData := string(buffer[:bytesRead])
		log.Printf("Server: Received and echoed back %d bytes from %s: %s", bytesRead, clientAddr, receivedData)
	}
	log.Printf("Server: Connection closed with %s", clientAddr)
}

func startTCPClient(iterations int, port int) {
	addr := fmt.Sprintf("localhost:%d", port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Client: Failed to connect to %s: %v", addr, err)
		return
	}
	defer conn.Close()

	log.Printf("Client: Connected to %s", addr)

	for i := 0; i < iterations; i++ {
		message := fmt.Sprintf("Ping %d: Hello from client at %s", i, time.Now().Format(time.RFC3339))
		bytesSent, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("Client: Failed to send data on iteration %d: %v", i, err)
			return
		}
		log.Printf("Client: Iteration %d: Sent %d bytes: %s", i, bytesSent, message)

		// Receive echo from server
		buffer := make([]byte, 1024)
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Client: Failed to read data on iteration %d: %v", i, err)
			return
		}
		echoedData := string(buffer[:bytesRead])
		log.Printf("Client: Iteration %d: Received %d bytes: %s", i, bytesRead, echoedData)

		// Sleep before next iteration
		time.Sleep(1 * time.Second)
	}
	log.Println("Client: Completed all iterations")
}
