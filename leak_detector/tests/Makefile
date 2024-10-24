# Makefile for compiling leaky_program.cpp with debug symbols and frame pointers preserved

# Compiler
CXX := g++

# Compiler flags
CXXFLAGS := -g -fno-omit-frame-pointer -O0

# Target executable
TARGET := leaky_program

# Source files
SRCS := leaky_program.cpp

# Default rule
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

# Clean up generated files
clean:
	rm -f $(TARGET)
