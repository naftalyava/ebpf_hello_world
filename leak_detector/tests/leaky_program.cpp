// leaky_program.cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdlib>   // For rand(), srand()
#include <ctime>     // For time()
#include <unistd.h>  // For getpid()
#include <functional>

// Function declarations
void startLeaking();
void leakMemory(int depth);
void workerFunction(int id);
void allocateAndLeak();
void recursiveLeak(int depth, int maxDepth);

int main() {
    // Seed the random number generator
    srand(static_cast<unsigned int>(time(0)));

    // Get and print the PID
    pid_t pid = getpid();
    std::cout << "Leaky program started with PID: " << pid << std::endl;

    // Start the leaking process in separate threads
    std::thread t1(startLeaking);
    std::thread t2(workerFunction, 1);
    std::thread t3(workerFunction, 2);

    // Wait for threads to finish (they won't in this case)
    t1.join();
    t2.join();
    t3.join();

    return 0;
}

void startLeaking() {
    while (true) {
        // Call different functions to leak memory
        leakMemory(rand() % 5 + 1);
        allocateAndLeak();
        recursiveLeak(0, 3);

        // Sleep for a short period
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void leakMemory(int depth) {
    if (depth <= 0) {
        // Base case: allocate memory and leak it
        size_t leakSize = (rand() % (1024 * 1024 - 1024 + 1)) + 1024;  // Between 1 KB and 1 MB
        void* mem = malloc(leakSize);
        if (mem == nullptr) {
            std::cerr << "Memory allocation failed in leakMemory!" << std::endl;
            return;
        }
        // Intentionally not freeing 'mem' to simulate a leak
        std::cout << "[leakMemory] Leaked " << leakSize << " bytes at depth 0." << std::endl;
    } else {
        // Recursive call
        leakMemory(depth - 1);
    }
}

void workerFunction(int id) {
    while (true) {
        // Simulate some work and leak
        std::cout << "[workerFunction " << id << "] Working..." << std::endl;
        allocateAndLeak();
        // Sleep for a short period
        std::this_thread::sleep_for(std::chrono::milliseconds(700 + id * 100));
    }
}

void allocateAndLeak() {
    // Allocate and leak memory
    size_t leakSize = (rand() % (512 * 1024 - 512 + 1)) + 512;  // Between 512 bytes and 512 KB
    void* mem = malloc(leakSize);
    if (mem == nullptr) {
        std::cerr << "Memory allocation failed in allocateAndLeak!" << std::endl;
        return;
    }
    // Intentionally not freeing 'mem' to simulate a leak
    std::cout << "[allocateAndLeak] Leaked " << leakSize << " bytes." << std::endl;
}

void recursiveLeak(int depth, int maxDepth) {
    // Recursive function to create deeper stack traces
    if (depth >= maxDepth) {
        // Allocate and leak memory
        size_t leakSize = (rand() % (256 * 1024 - 256 + 1)) + 256;  // Between 256 bytes and 256 KB
        void* mem = malloc(leakSize);
        if (mem == nullptr) {
            std::cerr << "Memory allocation failed in recursiveLeak!" << std::endl;
            return;
        }
        // Intentionally not freeing 'mem' to simulate a leak
        std::cout << "[recursiveLeak] Leaked " << leakSize << " bytes at max depth." << std::endl;
    } else {
        // Recursive call
        recursiveLeak(depth + 1, maxDepth);
    }
}
