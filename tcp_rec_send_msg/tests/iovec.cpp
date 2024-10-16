#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>

#define SERVER_PORT 8080
#define MAX_BUFFER_SIZE 512
#define NUM_ITERATIONS 1000
#define NUM_BUFFERS 3

// Function prototypes
void run_server(int port);
void run_client(int port, int iterations);

int main(int argc, char* argv[]) {
    pid_t pid = getpid();
    std::cout << "Main process started. PID: " << pid << std::endl;
    
    std::thread server_thread(run_server, SERVER_PORT);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    run_client(SERVER_PORT, NUM_ITERATIONS);
    
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    return 0;
}

void run_server(int port) {
    pid_t tid = gettid();
    std::cout << "Server thread started. TID: " << tid << std::endl;
    
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Server: Socket creation failed" << std::endl;
        return;
    }
    
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Server: setsockopt failed" << std::endl;
        return;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Server: Bind failed" << std::endl;
        return;
    }
    
    if (listen(server_fd, 1) < 0) {
        std::cerr << "Server: Listen failed" << std::endl;
        return;
    }
    
    std::cout << "Server: Listening on port " << port << std::endl;
    
    if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) < 0) {
        std::cerr << "Server: Accept failed" << std::endl;
        return;
    }
    
    std::cout << "Server: Client connected" << std::endl;

    // Prepare receive buffers for readv
    std::vector<std::vector<char>> recv_buffers(NUM_BUFFERS, std::vector<char>(MAX_BUFFER_SIZE));
    std::vector<struct iovec> recv_iov(NUM_BUFFERS);
    
    while (true) {
        // Setup iovec structures for receive
        for (int i = 0; i < NUM_BUFFERS; i++) {
            recv_iov[i].iov_base = recv_buffers[i].data();
            recv_iov[i].iov_len = MAX_BUFFER_SIZE;
        }
        
        // Receive data using readv
        ssize_t total_bytes_read = readv(client_fd, recv_iov.data(), NUM_BUFFERS);
        if (total_bytes_read <= 0) {
            break;
        }

        std::cout << "Server: Received total " << total_bytes_read << " bytes" << std::endl;

        // Process and echo back each received buffer
        ssize_t bytes_remaining = total_bytes_read;
        int buffer_index = 0;
        struct iovec send_iov[NUM_BUFFERS];
        int send_iov_count = 0;

        while (bytes_remaining > 0 && buffer_index < NUM_BUFFERS) {
            size_t buffer_bytes = std::min(static_cast<ssize_t>(MAX_BUFFER_SIZE), bytes_remaining);
            if (buffer_bytes > 0) {
                send_iov[send_iov_count].iov_base = recv_buffers[buffer_index].data();
                send_iov[send_iov_count].iov_len = buffer_bytes;
                send_iov_count++;

                std::cout << "Server: Buffer " << buffer_index + 1 << " contains: "
                         << std::string(recv_buffers[buffer_index].data(), buffer_bytes);
            }
            bytes_remaining -= buffer_bytes;
            buffer_index++;
        }

        // Echo back using writev
        if (send_iov_count > 0) {
            ssize_t bytes_sent = writev(client_fd, send_iov, send_iov_count);
            if (bytes_sent < 0) {
                std::cerr << "Server: writev failed" << std::endl;
                break;
            }
            std::cout << "Server: Echoed back " << bytes_sent << " bytes" << std::endl;
        }
    }
    
    close(client_fd);
    close(server_fd);
    std::cout << "Server: Shutting down" << std::endl;
}

void run_client(int port, int iterations) {
    pid_t tid = gettid();
    std::cout << "Client thread started. TID: " << tid << std::endl;
    
    int sock_fd;
    struct sockaddr_in server_addr;
    std::vector<char> recv_buffer(MAX_BUFFER_SIZE * NUM_BUFFERS);
    
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Client: Socket creation failed" << std::endl;
        return;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        std::cerr << "Client: Invalid address" << std::endl;
        return;
    }
    
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Client: Connection failed" << std::endl;
        return;
    }
    
    std::cout << "Client: Connected to server" << std::endl;
    
    for (int i = 0; i < iterations; i++) {
        // Create messages with different lengths
        std::string msg1 = "Buffer 1: Iteration " + std::to_string(i) + " (Short)\n";
        std::string msg2 = "Buffer 2: Iteration " + std::to_string(i) + " (Medium length message)\n";
        std::string msg3 = "Buffer 3: Iteration " + std::to_string(i) + " (This is a longer message to demonstrate variable length handling)\n";
        
        struct iovec iov[3];
        iov[0].iov_base = const_cast<char*>(msg1.c_str());
        iov[0].iov_len = msg1.length();
        iov[1].iov_base = const_cast<char*>(msg2.c_str());
        iov[1].iov_len = msg2.length();
        iov[2].iov_base = const_cast<char*>(msg3.c_str());
        iov[2].iov_len = msg3.length();
        
        // Calculate total message size
        size_t total_size = msg1.length() + msg2.length() + msg3.length();
        
        // Send using writev
        ssize_t bytes_sent = writev(sock_fd, iov, 3);
        if (bytes_sent < 0) {
            std::cerr << "Client: writev failed" << std::endl;
            break;
        }
        
        std::cout << "Client: Sent " << bytes_sent << " bytes using writev" << std::endl;
        
        // Prepare iovec for receiving response
        std::vector<std::vector<char>> recv_buffers(NUM_BUFFERS, std::vector<char>(MAX_BUFFER_SIZE));
        std::vector<struct iovec> recv_iov(NUM_BUFFERS);
        
        for (int j = 0; j < NUM_BUFFERS; j++) {
            recv_iov[j].iov_base = recv_buffers[j].data();
            recv_iov[j].iov_len = MAX_BUFFER_SIZE;
        }
        
        // Read echo response using readv
        ssize_t bytes_read = readv(sock_fd, recv_iov.data(), NUM_BUFFERS);
        if (bytes_read > 0) {
            std::cout << "Client: Received " << bytes_read << " bytes total" << std::endl;
            
            // Process received data
            ssize_t bytes_remaining = bytes_read;
            int buffer_index = 0;
            while (bytes_remaining > 0 && buffer_index < NUM_BUFFERS) {
                size_t buffer_bytes = std::min(static_cast<ssize_t>(MAX_BUFFER_SIZE), bytes_remaining);
                if (buffer_bytes > 0) {
                    std::cout << "Client: Received buffer " << buffer_index + 1 << ": "
                             << std::string(recv_buffers[buffer_index].data(), buffer_bytes);
                }
                bytes_remaining -= buffer_bytes;
                buffer_index++;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    close(sock_fd);
    std::cout << "Client: Shutting down" << std::endl;
}