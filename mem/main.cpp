#include <iostream>
#include <fstream>
#include <sstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

using namespace std;

#pragma comment(lib, "psapi.lib")

string GetProtectionString(DWORD protect) {
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

void EnumerateMemoryRegionsToFile(const string& exeName) {
    stringstream brah;
    brah << "memory regions for executable " << exeName << ":\n";

    wstring wideExeName(exeName.begin(), exeName.end());

    DWORD processId = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Process32First(snapshot, &entry)) {
            do {
                wstring wideEntryName(entry.szExeFile, entry.szExeFile + strlen(entry.szExeFile) + 1);

                if (_wcsicmp(wideEntryName.c_str(), wideExeName.c_str()) == 0) {
                    processId = entry.th32ProcessID;
                    brah << "PID: " << processId << "\n";
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    if (processId == 0) {
        cerr << "failed to find process for executable " << exeName << "\n";
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == nullptr) {
        cerr << "failed to open process for executable " << exeName << "\n";
        return;
    }

    ofstream file("memoenum.txt");
    if (!file.is_open()) {
        cerr << "unable to open file memoenum.txt\n";
        CloseHandle(hProcess);
        return;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(moduleEntry);

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t address = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);

    while (address < reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress)) {
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
            TCHAR szModule[MAX_PATH];
            if (::GetModuleFileNameEx(hProcess, (HMODULE)memInfo.AllocationBase, szModule, MAX_PATH)) {
                brah << "Base Address: " << reinterpret_cast<void*>(memInfo.BaseAddress)
                    << "; Region Size: " << memInfo.RegionSize << " bytes"
                    << "; Allocation Protect: " << GetProtectionString(memInfo.AllocationProtect)
                    << "; Module Name: " << szModule
                    << "\n";
            }
            else {
                brah << "Base Address: " << reinterpret_cast<void*>(memInfo.BaseAddress)
                    << "; Region Size: " << memInfo.RegionSize << " bytes"
                    << "; Allocation Protect: " << GetProtectionString(memInfo.AllocationProtect)
                    << "; Module Name: Unknown"
                    << "\n";
            }
            address += memInfo.RegionSize;
        }
        else {
            address += systemInfo.dwPageSize;
        }
    }

    file << brah.str();
    file.close();
    CloseHandle(hProcess);
    cout << "memory regions written to memoenum.txt\n";
}

int main() {
    string exeName;
    cout << "enter the executable filename (e.g., Discord.exe): ";
    getline(cin, exeName);

    EnumerateMemoryRegionsToFile(exeName);

    return 0;
}
