#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdlib>  // For rand(), srand()
#include <ctime>    // For time()
#include <unistd.h> // For getpid()

int main() {
    // Seed the random number generator
    srand(static_cast<unsigned int>(time(0)));

    // Get and print the PID
    pid_t pid = getpid();
    std::cout << "Leaky program started with PID: " << pid << std::endl;

    std::vector<void*> leaks;
    size_t totalLeaked = 0;

    while (true) {
        // Generate a random size between 1 KB and 1 MB
        size_t leakSize = (rand() % (1024 * 1024 - 1024 + 1)) + 1024; // Between 1 KB and 1 MB

        // Allocate memory
        void* mem = malloc(leakSize);
        if (mem == nullptr) {
            std::cerr << "Memory allocation failed!" << std::endl;
            return 1;
        }

        // Store the pointer to simulate a leak (not freeing it)
        leaks.push_back(mem);
        totalLeaked += leakSize;

        std::cout << "Leaked " << leakSize << " bytes. Total leaked: " << totalLeaked << " bytes." << std::endl;

        // Sleep for 1 second before next allocation
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
