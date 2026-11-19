#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
	struct SKSEPluginVersionData
	{
		std::uint32_t dataVersion{ 1 };
		std::uint32_t pluginVersion{ (1 << 24) };
		char          name[256]{ "AddressLibraryV5Shim" };
		char          author[256]{ "PluginUpdate" };
		char          supportEmail[252]{ "" };
		std::uint32_t versionIndependenceEx{ (1u << 0) | (1u << 1) }; // NoStructUse | AddressLibraryV5
		std::uint32_t versionIndependence{ (1u << 0) | (1u << 2) };   // AddressLibraryPostAE | StructsPost629
		std::uint32_t compatibleVersions[16]{};
		std::uint32_t seVersionRequired{ 0 };
	};
	static_assert(sizeof(SKSEPluginVersionData) == 0x350);

	struct SKSEInterface
	{
		std::uint32_t skseVersion;
		std::uint32_t runtimeVersion;
		std::uint32_t editorVersion;
		std::uint32_t isEditor;
		void* (*QueryInterface)(std::uint32_t id);
		std::uint32_t (*GetPluginHandle)();
		std::uint32_t (*GetReleaseIndex)();
		const void* (*GetPluginInfo)(const char* name);
	};

	std::wstring g_v2CachePath;
	std::wstring g_targetV5NameLib;
	std::wstring g_targetV5NameLegacy;

	struct PluginRange
	{
		std::uintptr_t base;
		std::uintptr_t end;
		bool           isPreV5;
	};

	SRWLOCK                  g_rangesLock = SRWLOCK_INIT;
	std::vector<PluginRange> g_pluginRanges;
	thread_local bool        t_redirectDuringLoad = false;

	bool GetSkyrimVersion(std::uint32_t outVer[4])
	{
		wchar_t exePath[MAX_PATH]{};
		if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
			return false;
		DWORD dummy = 0;
		DWORD sz = GetFileVersionInfoSizeW(exePath, &dummy);
		if (!sz)
			return false;
		std::vector<std::uint8_t> buf(sz);
		if (!GetFileVersionInfoW(exePath, 0, sz, buf.data()))
			return false;
		VS_FIXEDFILEINFO* ffi = nullptr;
		UINT len = 0;
		if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&ffi), &len) || !ffi)
			return false;
		outVer[0] = HIWORD(ffi->dwFileVersionMS);
		outVer[1] = LOWORD(ffi->dwFileVersionMS);
		outVer[2] = HIWORD(ffi->dwFileVersionLS);
		outVer[3] = LOWORD(ffi->dwFileVersionLS);
		return true;
	}

	bool ConvertV5ToV2(const std::filesystem::path& v5Path, const std::filesystem::path& v2Path)
	{
		std::ifstream in(v5Path, std::ios::binary);
		if (!in.is_open())
			return false;

		std::uint32_t fmt = 0;
		std::uint32_t ver[4]{};
		char modName[64]{};
		std::int32_t ptrSize = 8;
		std::int32_t dataFmt = 4;
		std::uint32_t offsetCount = 0;

		in.read(reinterpret_cast<char*>(&fmt), 4);
		if (!in || fmt != 5)
			return false;
		in.read(reinterpret_cast<char*>(ver), 16);
		in.read(modName, 64);
		in.read(reinterpret_cast<char*>(&ptrSize), 4);
		in.read(reinterpret_cast<char*>(&dataFmt), 4);
		in.read(reinterpret_cast<char*>(&offsetCount), 4);
		if (!in || offsetCount == 0 || offsetCount > 10000000u)
			return false;

		std::vector<std::uint32_t> offsets(offsetCount);
		in.read(reinterpret_cast<char*>(offsets.data()), static_cast<std::streamsize>(offsetCount) * 4);
		if (!in)
			return false;

		std::uint32_t validCount = 0;
		for (std::uint32_t off : offsets)
		{
			if (off != 0)
				++validCount;
		}

		std::vector<std::uint8_t> out;
		out.reserve(64 + static_cast<std::size_t>(validCount) * 6);

		auto pushBytes = [&](const void* p, std::size_t n) {
			const auto* b = static_cast<const std::uint8_t*>(p);
			out.insert(out.end(), b, b + n);
		};
		auto pushU32 = [&](std::uint32_t v) { pushBytes(&v, 4); };
		auto pushI32 = [&](std::int32_t v) { pushBytes(&v, 4); };

		pushI32(2); // Format 2
		pushBytes(ver, 16);
		const char tn[] = "SkyrimSE.exe";
		pushI32(12);
		pushBytes(tn, 12);
		pushI32(8); // ptrSize
		pushU32(validCount);

		std::uint64_t prevId = 0;
		std::uint64_t prevOff = 0;

		for (std::uint32_t id = 0; id < offsetCount; ++id)
		{
			std::uint64_t off = offsets[id];
			if (off == 0)
				continue;

			std::uint8_t low = 0;
			std::uint64_t idDelta = (id > prevId) ? (id - prevId) : 0;
			if (id == prevId + 1)
				low = 1;
			else if (id > prevId && idDelta <= 0xFF)
				low = 2;
			else if (id > prevId && idDelta <= 0xFFFF)
				low = 4;
			else
				low = 7;

			std::uint8_t high = 0;
			std::uint64_t offDelta = (off > prevOff) ? (off - prevOff) : 0;
			if (off == prevOff + 1)
				high = 1;
			else if (off > prevOff && offDelta <= 0xFF)
				high = 2;
			else if (off > prevOff && offDelta <= 0xFFFF)
				high = 4;
			else
				high = 7;

			std::uint8_t type = static_cast<std::uint8_t>((high << 4) | low);
			out.push_back(type);

			if (low == 2)
			{
				auto d = static_cast<std::uint8_t>(idDelta);
				out.push_back(d);
			}
			else if (low == 4)
			{
				auto d = static_cast<std::uint16_t>(idDelta);
				pushBytes(&d, 2);
			}
			else if (low == 7)
			{
				pushU32(id);
			}

			if (high == 2)
			{
				auto d = static_cast<std::uint8_t>(offDelta);
				out.push_back(d);
			}
			else if (high == 4)
			{
				auto d = static_cast<std::uint16_t>(offDelta);
				pushBytes(&d, 2);
			}
			else if (high == 7)
			{
				pushU32(static_cast<std::uint32_t>(off));
			}

			prevId = id;
			prevOff = off;
		}

		std::ofstream fout(v2Path, std::ios::binary | std::ios::trunc);
		if (!fout.is_open())
			return false;
		fout.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
		return fout.good();
	}

	bool IsTargetAddressLibNameW(const wchar_t* path)
	{
		if (!path || g_v2CachePath.empty())
			return false;
		const wchar_t* base = wcsrchr(path, L'\\');
		const wchar_t* base2 = wcsrchr(path, L'/');
		if (base2 && (!base || base2 > base))
			base = base2;
		base = base ? (base + 1) : path;

		std::size_t len = wcslen(base);
		if (len < 4 || _wcsicmp(base + len - 4, L".bin") != 0)
			return false;
		if (len >= 12 && _wcsicmp(base + len - 12, L".v2cache.bin") == 0)
			return false;

		if (!g_targetV5NameLib.empty() && _wcsicmp(base, g_targetV5NameLib.c_str()) == 0)
			return true;
		if (!g_targetV5NameLegacy.empty() && _wcsicmp(base, g_targetV5NameLegacy.c_str()) == 0)
			return true;

		const wchar_t* verPart = nullptr;
		if (_wcsnicmp(base, L"versionlib-", 11) == 0)
			verPart = base + 11;
		else if (_wcsnicmp(base, L"version-", 8) == 0)
			verPart = base + 8;
		if (!verPart)
			return false;

		unsigned int maj = 0;
		unsigned int min = 0;
		if (swscanf_s(verPart, L"%u-%u-", &maj, &min) == 2)
			return (maj > 1) || (maj == 1 && min >= 7);
		return false;
	}

	bool InspectModulePreV5(HMODULE mod, std::uintptr_t& outBase, std::uintptr_t& outEnd, bool& outIsPreV5)
	{
		if (!mod)
			return false;
		auto* base = reinterpret_cast<const std::uint8_t*>(mod);
		auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return false;
		outBase = reinterpret_cast<std::uintptr_t>(mod);
		outEnd = outBase + static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage);
		// 1748217600 = 2025-05-26 UTC (Format 5 introduction).
		outIsPreV5 = (nt->FileHeader.TimeDateStamp < 1748217600u);
		return true;
	}

	bool ShouldRedirectCaller()
	{
		void* frames[24]{};
		USHORT n = RtlCaptureStackBackTrace(1, 24, frames, nullptr);
		AcquireSRWLockShared(&g_rangesLock);
		for (USHORT i = 0; i < n; ++i)
		{
			auto addr = reinterpret_cast<std::uintptr_t>(frames[i]);
			for (const auto& r : g_pluginRanges)
			{
				if (addr >= r.base && addr < r.end)
				{
					bool res = r.isPreV5;
					ReleaseSRWLockShared(&g_rangesLock);
					return res;
				}
			}
		}
		ReleaseSRWLockShared(&g_rangesLock);
		return t_redirectDuringLoad;
	}

	using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	using CreateFileA_t = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	using GetFileAttributesExW_t = BOOL(WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
	using LoadLibraryW_t = HMODULE(WINAPI*)(LPCWSTR);
	using LoadLibraryExW_t = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
	using LoadLibraryA_t = HMODULE(WINAPI*)(LPCSTR);
	using LoadLibraryExA_t = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);

	CreateFileW_t          g_origCreateFileW = nullptr;
	CreateFileA_t          g_origCreateFileA = nullptr;
	GetFileAttributesExW_t g_origGetFileAttributesExW = nullptr;
	LoadLibraryW_t         g_origLoadLibraryW = nullptr;
	LoadLibraryExW_t       g_origLoadLibraryExW = nullptr;
	LoadLibraryA_t         g_origLoadLibraryA = nullptr;
	LoadLibraryExA_t       g_origLoadLibraryExA = nullptr;

	void PatchModuleIAT(HMODULE mod, const char* funcName, void* newFunc, void** outOrig);
	HANDLE WINAPI Hook_CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	HANDLE WINAPI Hook_CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	BOOL WINAPI Hook_GetFileAttributesExW(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);

	void HookPluginModule(HMODULE mod)
	{
		if (!mod)
			return;
		const bool isSksePlugin =
			GetProcAddress(mod, "SKSEPlugin_Version") ||
			GetProcAddress(mod, "SKSEPlugin_Load") ||
			GetProcAddress(mod, "SKSEPlugin_Query") ||
			GetProcAddress(mod, "SKSEPlugin_Preload");
		if (isSksePlugin)
		{
			std::uintptr_t base = 0;
			std::uintptr_t end = 0;
			bool isPreV5 = false;
			if (!InspectModulePreV5(mod, base, end, isPreV5))
				return;

			AcquireSRWLockExclusive(&g_rangesLock);
			bool updated = false;
			for (auto& r : g_pluginRanges)
			{
				if (r.base == base)
				{
					r.end = end;
					r.isPreV5 = isPreV5;
					updated = true;
					break;
				}
			}
			if (!updated)
				g_pluginRanges.push_back({ base, end, isPreV5 });
			ReleaseSRWLockExclusive(&g_rangesLock);

			if (!isPreV5)
				return;
		}
		PatchModuleIAT(mod, "CreateFileW", reinterpret_cast<void*>(&Hook_CreateFileW), reinterpret_cast<void**>(&g_origCreateFileW));
		PatchModuleIAT(mod, "CreateFileA", reinterpret_cast<void*>(&Hook_CreateFileA), reinterpret_cast<void**>(&g_origCreateFileA));
		PatchModuleIAT(mod, "GetFileAttributesExW", reinterpret_cast<void*>(&Hook_GetFileAttributesExW), reinterpret_cast<void**>(&g_origGetFileAttributesExW));
	}

	bool ShouldRedirectPathW(LPCWSTR path)
	{
		if (!path || !*path)
			return false;
		// Only inspect DLLs under SKSE\Plugins\.
		bool inPlugins = false;
		for (const wchar_t* p = path; *p; ++p)
		{
			if ((_wcsnicmp(p, L"skse\\plugins\\", 13) == 0) || (_wcsnicmp(p, L"skse/plugins/", 13) == 0))
			{
				inPlugins = true;
				break;
			}
		}
		if (!inPlugins)
			return false;

		HANDLE hFile = g_origCreateFileW
			? g_origCreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)
			: CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		std::uint8_t buf[4096]{};
		DWORD bytesRead = 0;
		BOOL ok = ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr);
		CloseHandle(hFile);
		if (!ok || bytesRead < sizeof(IMAGE_DOS_HEADER))
			return false;

		auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
			static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytesRead)
			return false;

		auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		return (nt->FileHeader.TimeDateStamp < 1748217600u);
	}

	bool ShouldRedirectPathA(LPCSTR path)
	{
		if (!path || !*path)
			return false;
		int needed = MultiByteToWideChar(CP_ACP, 0, path, -1, nullptr, 0);
		if (needed <= 0)
			return false;
		std::wstring wbuf(static_cast<std::size_t>(needed), L'\0');
		if (MultiByteToWideChar(CP_ACP, 0, path, -1, wbuf.data(), needed) <= 0)
			return false;
		return ShouldRedirectPathW(wbuf.c_str());
	}

	struct ScopedLoadRedirect
	{
		bool prev;
		explicit ScopedLoadRedirect(bool active) noexcept : prev(t_redirectDuringLoad)
		{
			t_redirectDuringLoad = active;
		}
		~ScopedLoadRedirect()
		{
			t_redirectDuringLoad = prev;
		}
	};

	HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName)
	{
		ScopedLoadRedirect guard(ShouldRedirectPathW(lpLibFileName));
		HMODULE mod = g_origLoadLibraryW(lpLibFileName);
		HookPluginModule(mod);
		return mod;
	}

	HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		const bool resolve = !(dwFlags & (DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE));
		HMODULE mod = nullptr;
		if (resolve)
		{
			ScopedLoadRedirect guard(ShouldRedirectPathW(lpLibFileName));
			mod = g_origLoadLibraryExW(lpLibFileName, hFile, dwFlags);
		}
		else
		{
			mod = g_origLoadLibraryExW(lpLibFileName, hFile, dwFlags);
		}
		if (mod && resolve)
			HookPluginModule(mod);
		return mod;
	}

	HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName)
	{
		ScopedLoadRedirect guard(ShouldRedirectPathA(lpLibFileName));
		HMODULE mod = g_origLoadLibraryA(lpLibFileName);
		HookPluginModule(mod);
		return mod;
	}

	HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		const bool resolve = !(dwFlags & (DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE));
		HMODULE mod = nullptr;
		if (resolve)
		{
			ScopedLoadRedirect guard(ShouldRedirectPathA(lpLibFileName));
			mod = g_origLoadLibraryExA(lpLibFileName, hFile, dwFlags);
		}
		else
		{
			mod = g_origLoadLibraryExA(lpLibFileName, hFile, dwFlags);
		}
		if (mod && resolve)
			HookPluginModule(mod);
		return mod;
	}

	HANDLE WINAPI Hook_CreateFileW(
		LPCWSTR lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile)
	{
		if (IsTargetAddressLibNameW(lpFileName) && ShouldRedirectCaller())
			lpFileName = g_v2CachePath.c_str();
		return g_origCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	HANDLE WINAPI Hook_CreateFileA(
		LPCSTR lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile)
	{
		if (lpFileName && !g_v2CachePath.empty())
		{
			int needed = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, nullptr, 0);
			if (needed > 0)
			{
				std::wstring wbuf(static_cast<std::size_t>(needed), L'\0');
				if (MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wbuf.data(), needed) > 0 &&
					IsTargetAddressLibNameW(wbuf.c_str()) && ShouldRedirectCaller())
				{
					return g_origCreateFileW(g_v2CachePath.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
				}
			}
		}
		return g_origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	BOOL WINAPI Hook_GetFileAttributesExW(
		LPCWSTR lpFileName,
		GET_FILEEX_INFO_LEVELS fInfoLevelId,
		LPVOID lpFileInformation)
	{
		if (IsTargetAddressLibNameW(lpFileName) && ShouldRedirectCaller())
			lpFileName = g_v2CachePath.c_str();
		return g_origGetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
	}

	// Patch IAT of a loaded module (e.g. ucrtbase/msvcp140/plugins) or kernel32->KERNELBASE
	void PatchModuleIAT(HMODULE mod, const char* funcName, void* newFunc, void** outOrig)
	{
		if (!mod)
			return;
		auto* base = reinterpret_cast<std::uint8_t*>(mod);
		auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return;
		auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return;
		auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!dir.VirtualAddress || !dir.Size)
			return;
		auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
		for (; imp->Name; ++imp)
		{
			auto* oft = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + imp->OriginalFirstThunk);
			auto* ft = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + imp->FirstThunk);
			if (!imp->OriginalFirstThunk)
				oft = ft;
			for (; oft->u1.AddressOfData; ++oft, ++ft)
			{
				if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal))
					continue;
				auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + oft->u1.AddressOfData);
				if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), funcName) == 0)
				{
					DWORD oldProt = 0;
					if (VirtualProtect(&ft->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt))
					{
						if (outOrig && !*outOrig)
							*outOrig = reinterpret_cast<void*>(ft->u1.Function);
						ft->u1.Function = reinterpret_cast<std::uint64_t>(newFunc);
						VirtualProtect(&ft->u1.Function, sizeof(void*), oldProt, &oldProt);
					}
				}
			}
		}
	}
}

extern "C" __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version{};

extern "C" __declspec(dllexport) bool SKSEPlugin_Preload(const SKSEInterface* skse)
{
	(void)skse;
	std::uint32_t ver[4]{};
	if (!GetSkyrimVersion(ver) || (ver[0] < 1) || (ver[0] == 1 && ver[1] < 7))
		return true;

	wchar_t nameBuf[128]{};
	swprintf_s(nameBuf, L"Data\\SKSE\\Plugins\\versionlib-%u-%u-%u-%u.bin", ver[0], ver[1], ver[2], ver[3]);
	wchar_t baseLibBuf[128]{};
	swprintf_s(baseLibBuf, L"versionlib-%u-%u-%u-%u.bin", ver[0], ver[1], ver[2], ver[3]);
	wchar_t baseLegacyBuf[128]{};
	swprintf_s(baseLegacyBuf, L"version-%u-%u-%u-%u.bin", ver[0], ver[1], ver[2], ver[3]);
	wchar_t cacheBuf[128]{};
	swprintf_s(cacheBuf, L"Data\\SKSE\\Plugins\\versionlib-%u-%u-%u-%u.v2cache.bin", ver[0], ver[1], ver[2], ver[3]);

	std::filesystem::path v5Path(nameBuf);
	std::filesystem::path v2Path(cacheBuf);
	if (!std::filesystem::exists(v5Path))
		return true;

	if (!std::filesystem::exists(v2Path) ||
		std::filesystem::last_write_time(v2Path) < std::filesystem::last_write_time(v5Path))
	{
		if (!ConvertV5ToV2(v5Path, v2Path))
			return true;
	}

	g_targetV5NameLib = baseLibBuf;
	g_targetV5NameLegacy = baseLegacyBuf;
	g_v2CachePath = v2Path.wstring();

	// Hook CreateFileW and GetFileAttributesExW in ucrtbase/msvcp140 (for /MD plugins),
	// and hook LoadLibraryW/LoadLibraryExW ONLY on skse64_*.dll so we patch each plugin's
	// IAT safely after LoadLibrary returns (never touching kernel32/ntdll or DllMain Loader Lock).
	HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
	g_origCreateFileW = reinterpret_cast<CreateFileW_t>(GetProcAddress(k32, "CreateFileW"));
	g_origCreateFileA = reinterpret_cast<CreateFileA_t>(GetProcAddress(k32, "CreateFileA"));
	g_origGetFileAttributesExW = reinterpret_cast<GetFileAttributesExW_t>(GetProcAddress(k32, "GetFileAttributesExW"));
	g_origLoadLibraryW = reinterpret_cast<LoadLibraryW_t>(GetProcAddress(k32, "LoadLibraryW"));
	g_origLoadLibraryExW = reinterpret_cast<LoadLibraryExW_t>(GetProcAddress(k32, "LoadLibraryExW"));
	g_origLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(GetProcAddress(k32, "LoadLibraryA"));
	g_origLoadLibraryExA = reinterpret_cast<LoadLibraryExA_t>(GetProcAddress(k32, "LoadLibraryExA"));

	const wchar_t* crtMods[] = { L"ucrtbase.dll", L"msvcp140.dll" };
	for (const wchar_t* m : crtMods)
	{
		HookPluginModule(GetModuleHandleW(m));
	}

	HMODULE mods[1024]{};
	DWORD needed = 0;
	if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
	{
		DWORD count = needed / sizeof(HMODULE);
		for (DWORD i = 0; i < count && i < 1024; ++i)
		{
			wchar_t baseName[MAX_PATH]{};
			if (!GetModuleBaseNameW(GetCurrentProcess(), mods[i], baseName, MAX_PATH))
				continue;
			if (_wcsnicmp(baseName, L"skse64_", 7) == 0)
			{
				HookPluginModule(mods[i]);
				PatchModuleIAT(mods[i], "LoadLibraryW", reinterpret_cast<void*>(&Hook_LoadLibraryW), reinterpret_cast<void**>(&g_origLoadLibraryW));
				PatchModuleIAT(mods[i], "LoadLibraryExW", reinterpret_cast<void*>(&Hook_LoadLibraryExW), reinterpret_cast<void**>(&g_origLoadLibraryExW));
				PatchModuleIAT(mods[i], "LoadLibraryA", reinterpret_cast<void*>(&Hook_LoadLibraryA), reinterpret_cast<void**>(&g_origLoadLibraryA));
				PatchModuleIAT(mods[i], "LoadLibraryExA", reinterpret_cast<void*>(&Hook_LoadLibraryExA), reinterpret_cast<void**>(&g_origLoadLibraryExA));
			}
		}
	}
	return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface* skse)
{
	(void)skse;
	return true;
}
