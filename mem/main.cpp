#include <iostream>
#include <string>
#include "include/memutils.h"

using namespace std;

int main() {
    string exeName;
    cout << "Enter the executable filename (e.g., Discord.exe): ";
    getline(cin, exeName);

    EnumerateMemoryAndWriteToFile(exeName);

    return 0;
}
