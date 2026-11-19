#include "PCH.h"

namespace
{
    void CheckAddressesAndState()
    {
        // 1. Legacy single-runtime SE (1.5.97) ID that needs REL::RelocationID(se_id, ae_id)
        REL::Relocation<std::uintptr_t> uiSingleton{ REL::ID(514287) };

        // 2. AE ID 47286 existed in 1.6.640 & 1.6.1170, but split to 523983 in 1.7.99+!
        REL::Relocation<std::uintptr_t> projTargetFunc{ REL::RelocationID(46022, 47286) };

        SKSE::log::info("ModA resolved addresses: {:x}, {:x}", uiSingleton.address(), projTargetFunc.address());
    }

    void OnMessage(SKSE::MessagingInterface::Message* a_msg)
    {
        if (a_msg && a_msg->type == SKSE::MessagingInterface::kDataLoaded) {
            CheckAddressesAndState();
        }
    }
}

SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    SKSE::Init(a_skse);
    if (const auto messaging = SKSE::GetMessagingInterface()) {
        messaging->RegisterListener(OnMessage);
    }
    return true;
}
