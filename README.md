# Memory Region Enumerator

This C++ program enumerates memory regions for a specified executable using Windows APIs. It retrieves information about memory allocation, protection, and module names.

## Features

- Enumerates memory regions for a specified executable.
- Displays base address, region size, allocation protection, and module name (if available).
- Outputs the results to a text file (`memoenum.txt`).

## Prerequisites

- Windows operating system.
- C++ compiler (tested with g++ on Windows).
- Psapi library (linked with `-lPsapi`).

## Usage

1. **Compilation:**
   Compile the program using a C++ compiler. For example, with g++:

   ```bash
   g++ main.cpp -o main.exe -lPsapi
