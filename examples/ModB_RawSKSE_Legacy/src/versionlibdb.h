#pragma once
// Legacy Format-2-only versionlibdb.h (breaks on Skyrim 1.7.99+ Format 5!)
#include <windows.h>
#include <fstream>
#include <map>
#include <string>

class VersionDb
{
public:
    bool Load()
    {
        std::ifstream file("Data\\SKSE\\Plugins\\versionlib-1-6-1170-0.bin", std::ios::binary);
        int format = 0;
        file.read(reinterpret_cast<char*>(&format), sizeof(int));
        if (format != 2)
            return false;
        return true;
    }
    void* FindAddressById(unsigned long long id) const { (void)id; return nullptr; }
};
