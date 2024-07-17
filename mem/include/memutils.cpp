#include "memutils.h"
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

std::string convertProtectionToString(DWORD protect) {
    if (protect & PAGE_NOACCESS)
        return "No Access";
    else if (protect & PAGE_READONLY)
        return "Read Only";
    else if (protect & PAGE_READWRITE)
        return "Read/Write";
    else if (protect & PAGE_WRITECOPY)
        return "Write Copy";
    else if (protect & PAGE_EXECUTE)
        return "Execute";
    else if (protect & PAGE_EXECUTE_READ)
        return "Execute/Read";
    else if (protect & PAGE_EXECUTE_READWRITE)
        return "Execute/Read/Write";
    else if (protect & PAGE_EXECUTE_WRITECOPY)
        return "Execute/Write Copy";
    else
        return "Unknown";
}

DWORD findProcessID(const std::string& exeName) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to create toolhelp snapshot" << std::endl;
        return 0;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, exeName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        std::cerr << "Error: Unable to get the first process" << std::endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}

void EnumerateMemoryAndWriteToFile(const std::string& exeName) {
    std::string output;
    output += "Memory regions for executable " + exeName + ":\n";

    DWORD pid = findProcessID(exeName);
    if (pid == 0) {
        std::cerr << "Failed to find process for executable: " << exeName << std::endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == nullptr) {
        std::cerr << "Failed to open process for executable: " << exeName << std::endl;
        return;
    }

    std::ofstream file("memoenum.txt");
    if (!file.is_open()) {
        std::cerr << "Unable to open file: memoenum.txt" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // start at the minimum application address
    uintptr_t address = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);

    // iterate over memory regions
    while (address < reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress)) {
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            char moduleName[MAX_PATH] = "Unknown";
            GetModuleFileNameExA(hProcess, (HMODULE)memInfo.AllocationBase, moduleName, MAX_PATH);

            output += "Base Address: " + std::to_string(reinterpret_cast<uintptr_t>(memInfo.BaseAddress)) +
                "; Region Size: " + std::to_string(memInfo.RegionSize) + " bytes" +
                "; Allocation Protect: " + convertProtectionToString(memInfo.AllocationProtect) +
                "; Module Name: " + std::string(moduleName) + "\n";

            address += memInfo.RegionSize;
        }
        else {
            address += sysInfo.dwPageSize;
        }
    }

    file << output;
    file.close();
    CloseHandle(hProcess);
    std::cout << "Memory regions written to memoenum.txt" << std::endl;
}
