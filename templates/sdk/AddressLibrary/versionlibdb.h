#pragma once

// ============================================================================
// Upgraded Address Library Header (versionlibdb.h) for SKSE64 Plugins
// Supports:
//   - Format 1 (Skyrim SE 1.5.x: Data\SKSE\Plugins\version-X-X-X-X.bin)
//   - Format 2 (Skyrim AE 1.6.x: Data\SKSE\Plugins\versionlib-1-6-X-X.bin)
//   - Format 5 (Skyrim AE 1.7.99 / 1.7.104+: Data\SKSE\Plugins\versionlib-1-7-X-X.bin)
//
// Drop-in replacement for meh321's original versionlibdb.h / versiondb.h.
// IMPORTANT: When compiling a raw SKSE64 plugin for 1.7.99 / 1.7.104+, ensure your
// exported SKSEPlugin_Version sets:
//   versionIndependenceEx = SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5
//   (or 1 << 1, or combined with kVersionIndependentEx_NoStructUse = 1 << 0 -> 0x3)
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "version.lib")

class VersionDb
{
public:
    VersionDb() { Clear(); }
    ~VersionDb() { }

private:
    std::map<unsigned long long, unsigned long long> _data;
    std::map<unsigned long long, unsigned long long> _rdata;
    int _ver[4];
    std::string _verStr;
    std::string _moduleName;
    unsigned long long _base;
    int _loadedFormat;

    template <typename T>
    static T read(std::ifstream& file)
    {
        T v{};
        file.read(reinterpret_cast<char*>(&v), sizeof(T));
        return v;
    }

    static void* ToPointer(unsigned long long v)
    {
        return reinterpret_cast<void*>(v);
    }

    static unsigned long long FromPointer(void* ptr)
    {
        return reinterpret_cast<unsigned long long>(ptr);
    }

    static bool ParseVersionFromString(const char* ptr, int& major, int& minor, int& revision, int& build)
    {
        return sscanf_s(ptr, "%d-%d-%d-%d", &major, &minor, &revision, &build) == 4 &&
               ((major != 1 && major != 0) || minor != 0 || revision != 0 || build != 0);
    }

public:
    const std::string& GetModuleName() const { return _moduleName; }
    const std::string& GetLoadedVersionString() const { return _verStr; }
    const std::map<unsigned long long, unsigned long long>& GetOffsetMap() const { return _data; }
    unsigned long long GetModuleBase() const { return _base; }
    int GetLoadedFormat() const { return _loadedFormat; }

    void* FindAddressById(unsigned long long id) const
    {
        unsigned long long b = _base;
        if (b == 0)
            return NULL;

        unsigned long long offset = 0;
        if (!FindOffsetById(id, offset))
            return NULL;

        return ToPointer(b + offset);
    }

    bool FindOffsetById(unsigned long long id, unsigned long long& result) const
    {
        auto itr = _data.find(id);
        if (itr != _data.end())
        {
            result = itr->second;
            return true;
        }
        return false;
    }

    bool FindIdByAddress(void* ptr, unsigned long long& result) const
    {
        unsigned long long b = _base;
        if (b == 0)
            return false;

        unsigned long long addr = FromPointer(ptr);
        return FindIdByOffset(addr - b, result);
    }

    bool FindIdByOffset(unsigned long long offset, unsigned long long& result) const
    {
        auto itr = _rdata.find(offset);
        if (itr == _rdata.end())
            return false;

        result = itr->second;
        return true;
    }

    bool GetExecutableVersion(int& major, int& minor, int& revision, int& build) const
    {
        TCHAR szFilename[MAX_PATH + 1] = { 0 };
        if (GetModuleFileName(NULL, szFilename, MAX_PATH) == 0)
            return false;

        DWORD dummy = 0;
        DWORD dwSize = GetFileVersionInfoSize(szFilename, &dummy);
        if (dwSize == 0)
            return false;

        std::string buffer(dwSize, '\0');
        if (!GetFileVersionInfo(szFilename, 0, dwSize, &buffer[0]))
            return false;

        void* ppvProductVersion = NULL;
        UINT iProductVersionLen = 0;
        if (!VerQueryValue(&buffer[0], TEXT("\\"), &ppvProductVersion, &iProductVersionLen))
            return false;

        if (iProductVersionLen < sizeof(VS_FIXEDFILEINFO))
            return false;

        VS_FIXEDFILEINFO* ffi = reinterpret_cast<VS_FIXEDFILEINFO*>(ppvProductVersion);
        major = HIWORD(ffi->dwFileVersionMS);
        minor = LOWORD(ffi->dwFileVersionMS);
        revision = HIWORD(ffi->dwFileVersionLS);
        build = LOWORD(ffi->dwFileVersionLS);

        return true;
    }

    void Clear()
    {
        _data.clear();
        _rdata.clear();
        for (int i = 0; i < 4; i++) _ver[i] = 0;
        _moduleName = std::string();
        _verStr = std::string();
        _base = 0;
        _loadedFormat = 0;
    }

    bool Load()
    {
        int major, minor, revision, build;
        if (!GetExecutableVersion(major, minor, revision, build))
            return false;

        return Load(major, minor, revision, build);
    }

    bool Load(int major, int minor, int revision, int build)
    {
        Clear();

        char fileName[256];
        // AE is minor >= 6 (1.6.x, 1.7.x+). SE is minor <= 5 (1.5.x).
        if (minor >= 6)
        {
            _snprintf_s(fileName, 256, "Data\\SKSE\\Plugins\\versionlib-%d-%d-%d-%d.bin", major, minor, revision, build);
            if (LoadFromFile(fileName))
                return true;
        }
        _snprintf_s(fileName, 256, "Data\\SKSE\\Plugins\\version-%d-%d-%d-%d.bin", major, minor, revision, build);
        return LoadFromFile(fileName);
    }

    bool LoadFromFile(const char* path)
    {
        Clear();

        std::ifstream file = std::ifstream(path, std::ios::binary);
        if (!file.good())
            return false;

        int format = read<int>(file);

        // Format 1 (SE 1.5.x) and Format 2 (AE 1.6.x)
        if (format == 1 || format == 2)
        {
            _loadedFormat = format;
            for (int i = 0; i < 4; i++)
                _ver[i] = read<int>(file);

            {
                std::stringstream str;
                for (int i = 0; i < 4; i++)
                {
                    if (i != 0)
                        str << "-";
                    str << _ver[i];
                }
                _verStr = str.str();
            }

            int nameLen = read<int>(file);
            if (nameLen < 0 || nameLen >= 0x10000)
                return false;

            {
                std::string buf(static_cast<size_t>(nameLen), '\0');
                if (nameLen > 0)
                    file.read(&buf[0], nameLen);
                _moduleName = buf;
            }

            _base = FromPointer(GetModuleHandleA(_moduleName.empty() ? NULL : _moduleName.c_str()));
            if (_base == 0)
                _base = FromPointer(GetModuleHandleA(NULL));

            int pointerSize = read<int>(file);
            int addrCount = read<int>(file);

            unsigned char type, low, high;
            unsigned char b1, b2;
            unsigned short w1, w2;
            unsigned int d1, d2;
            unsigned long long q1, q2;
            unsigned long long pvid = 0;
            unsigned long long poffs = 0;
            unsigned long long tpoffs;

            for (int i = 0; i < addrCount; i++)
            {
                type = read<unsigned char>(file);
                low = type & 0xF;
                high = type >> 4;

                switch (low)
                {
                case 0: q1 = read<unsigned long long>(file); break;
                case 1: q1 = pvid + 1; break;
                case 2: b1 = read<unsigned char>(file); q1 = pvid + b1; break;
                case 3: b1 = read<unsigned char>(file); q1 = pvid - b1; break;
                case 4: w1 = read<unsigned short>(file); q1 = pvid + w1; break;
                case 5: w1 = read<unsigned short>(file); q1 = pvid - w1; break;
                case 6: w1 = read<unsigned short>(file); q1 = w1; break;
                case 7: d1 = read<unsigned int>(file); q1 = d1; break;
                default:
                    Clear();
                    return false;
                }

                tpoffs = (high & 8) != 0 ? (poffs / static_cast<unsigned long long>(pointerSize)) : poffs;

                switch (high & 7)
                {
                case 0: q2 = read<unsigned long long>(file); break;
                case 1: q2 = tpoffs + 1; break;
                case 2: b2 = read<unsigned char>(file); q2 = tpoffs + b2; break;
                case 3: b2 = read<unsigned char>(file); q2 = tpoffs - b2; break;
                case 4: w2 = read<unsigned short>(file); q2 = tpoffs + w2; break;
                case 5: w2 = read<unsigned short>(file); q2 = tpoffs - w2; break;
                case 6: w2 = read<unsigned short>(file); q2 = w2; break;
                case 7: d2 = read<unsigned int>(file); q2 = d2; break;
                default:
                    Clear();
                    return false;
                }

                if ((high & 8) != 0)
                    q2 *= static_cast<unsigned long long>(pointerSize);

                _data[q1] = q2;
                _rdata[q2] = q1;

                poffs = q2;
                pvid = q1;
            }

            return true;
        }
        // Format 5 (AE 1.7.99 / 1.7.104+)
        else if (format == 5)
        {
            _loadedFormat = 5;
            for (int i = 0; i < 4; i++)
                _ver[i] = static_cast<int>(read<unsigned int>(file));

            {
                std::stringstream str;
                for (int i = 0; i < 4; i++)
                {
                    if (i != 0)
                        str << "-";
                    str << _ver[i];
                }
                _verStr = str.str();
            }

            char nameBuf[65] = { 0 };
            file.read(nameBuf, 64);
            nameBuf[64] = '\0';
            _moduleName = std::string(nameBuf);

            _base = FromPointer(GetModuleHandleA(_moduleName.empty() ? NULL : _moduleName.c_str()));
            if (_base == 0)
                _base = FromPointer(GetModuleHandleA(NULL));

            int pointerSize = read<int>(file);
            int dataFormat = read<int>(file);
            int offsetCount = read<int>(file);
            (void)pointerSize;
            (void)dataFormat;

            if (offsetCount < 0)
            {
                Clear();
                return false;
            }

            for (int id = 0; id < offsetCount; id++)
            {
                unsigned int rawOffset = read<unsigned int>(file);
                if (!file.good() && id + 1 < offsetCount)
                {
                    Clear();
                    return false;
                }
                if (rawOffset != 0)
                {
                    unsigned long long q1 = static_cast<unsigned long long>(id);
                    unsigned long long q2 = static_cast<unsigned long long>(rawOffset);
                    _data[q1] = q2;
                    _rdata[q2] = q1;
                }
            }

            return true;
        }

        return false;
    }

    bool Dump(const std::string& path)
    {
        std::ofstream f = std::ofstream(path.c_str());
        if (!f.good())
            return false;

        for (auto itr = _data.begin(); itr != _data.end(); ++itr)
        {
            f << std::dec << itr->first << '\t' << std::hex << std::setfill('0') << std::setw(7) << itr->second << '\n';
        }

        return true;
    }
};
