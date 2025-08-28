/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DP_STATIC_PROFILE_MANAGER_H
#define OHOS_DP_STATIC_PROFILE_MANAGER_H

#include "dm_device_info.h"
#include "iremote_object.h"

#include "characteristic_profile.h"
#include "dp_sync_options.h"
#include "kv_adapter.h"
#include "single_instance.h"
#include "trusted_device_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class StaticProfileManager {
DECLARE_SINGLE_INSTANCE(StaticProfileManager);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, CharacteristicProfile& charProfile);
    int32_t GetAllCharacteristicProfile(std::vector<CharacteristicProfile>& staticCapabilityProfiles);
    void E2ESyncStaticProfile(const TrustedDeviceInfo& deviceInfo);
    int32_t SyncStaticProfile(const DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback);
    void GetSyncListeners(std::map<std::string, sptr<IRemoteObject>>& syncListeners);
    void RemoveSyncListeners(std::map<std::string, sptr<IRemoteObject>> syncListeners);

private:
    int32_t GenerateStaticInfoProfile(const CharacteristicProfile& staticCapabilityProfile,
        std::unordered_map<std::string, CharacteristicProfile>& staticInfoProfiles);
    int32_t AddSyncListener(const std::string& caller, sptr<IRemoteObject> syncListener);

private:
    std::mutex staticStoreMutex_;
    std::shared_ptr<IKVAdapter> staticProfileStore_ = nullptr;
    std::mutex syncListenerMapMutex_;
    std::map<std::string, sptr<IRemoteObject>> syncListenerMap_;
    sptr<IRemoteObject::DeathRecipient> syncListenerDeathRecipient_ = nullptr;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_STATIC_PROFILE_MANAGER_H
