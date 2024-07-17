#include <iostream>
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

using namespace std;

#pragma comment(lib, "psapi.lib")

// func to map memory protection constants to readable strings
string convertProtectionToString(DWORD protect) {
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

// func to find process ID by exec name
DWORD findProcessID(const string& exeName) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cerr << "Error: Unable to create toolhelp snapshot" << endl;
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
        cerr << "Error: Unable to get the first process" << endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}

// main func to enum memory regions and write to file
void EnumerateMemoryAndWriteToFile(const string& exeName) {
    string output;
    output += "Memory regions for executable " + exeName + ":\n";

    DWORD pid = findProcessID(exeName);
    if (pid == 0) {
        cerr << "Failed to find process for executable: " << exeName << endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == nullptr) {
        cerr << "Failed to open process for executable: " << exeName << endl;
        return;
    }

    ofstream file("memoenum.txt");
    if (!file.is_open()) {
        cerr << "Unable to open file: memoenum.txt" << endl;
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

            output += "Base Address: " + to_string(reinterpret_cast<uintptr_t>(memInfo.BaseAddress)) +
                "; Region Size: " + to_string(memInfo.RegionSize) + " bytes" +
                "; Allocation Protect: " + convertProtectionToString(memInfo.AllocationProtect) +
                "; Module Name: " + string(moduleName) + "\n";

            address += memInfo.RegionSize;
        }
        else {
            address += sysInfo.dwPageSize;
        }
    }

    file << output;
    file.close();
    CloseHandle(hProcess);
    cout << "Memory regions written to memoenum.txt" << endl;
}

int main() {
    string exeName;
    cout << "Enter the executable filename (e.g., Discord.exe): ";
    getline(cin, exeName);

    EnumerateMemoryAndWriteToFile(exeName);

    return 0;
}
