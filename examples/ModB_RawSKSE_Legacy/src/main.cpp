#include <windows.h>
#include "skse64/PluginAPI.h"
#include "skse64_common/skse_version.h"
#include "versionlibdb.h"

extern "C" {
    __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
        SKSEPluginVersionData::kVersion,
        1,
        "ModB_RawSKSE_Legacy",
        "LegacyAuthor",
        "support@example.com",
        SKSEPluginVersionData::kVersionIndependentEx_NoStructUse, // Missing kVersionIndependentEx_AddressLibraryV5!
        SKSEPluginVersionData::kVersionIndependent_AddressLibraryPostAE,
        { RUNTIME_VERSION_1_6_1170, 0 },
        0,
    };

    __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface* skse)
    {
        if (!skse)
            return false;

        VersionDb db;
        if (!db.Load())
            return false;

        void* addr = db.FindAddressById(400449);
        return addr != nullptr;
    }
}
