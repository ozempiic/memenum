#pragma once

#include <string>
#include <Windows.h>

std::string convertProtectionToString(DWORD protect);
DWORD findProcessID(const std::string& exeName);
void EnumerateMemoryAndWriteToFile(const std::string& exeName);
