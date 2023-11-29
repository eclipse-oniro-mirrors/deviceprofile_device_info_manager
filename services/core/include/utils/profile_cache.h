/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_PROFILE_CACHE_H
#define OHOS_DP_PROFILE_CACHE_H

#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <vector>
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "dp_subscribe_info.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "single_instance.h"
#include "distributed_device_profile_constants.h"
#include "iremote_object.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileCache {
    DECLARE_SINGLE_INSTANCE(ProfileCache);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t AddDeviceProfile(const DeviceProfile& deviceProfile);
    int32_t AddServiceProfile(const ServiceProfile& serviceProfile);
    int32_t AddCharProfile(const CharacteristicProfile& charProfile);
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile);
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& charKey, CharacteristicProfile& charProfile);
    int32_t DeleteDeviceProfile(const std::string& deviceId);
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName);
    int32_t DeleteCharProfile(const std::string& deviceId, const std::string& serviceName, const std::string& charKey);
    bool IsDeviceProfileExist(const DeviceProfile& deviceProfile);
    bool IsServiceProfileExist(const ServiceProfile& serviceProfile);
    bool IsCharProfileExist(const CharacteristicProfile& charProfile);
    int32_t RefreshProfileCache();
    int32_t AddSyncListener(const std::string& caller, sptr<IRemoteObject> syncListener);
    int32_t GetSyncListeners(std::map<std::string, sptr<IRemoteObject>>& syncListeners);
    int32_t RemoveSyncListeners(std::map<std::string, sptr<IRemoteObject>> syncListeners);
    int32_t RemoveSyncListener(const std::string& caller);
    int32_t RemoveSyncListener(sptr<IRemoteObject> syncListener);

private:
    int32_t RefreshDeviceProfileCache(const std::vector<DeviceProfile>& deviceProfiles);
    int32_t RefreshServiceProfileCache(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t RefreshCharProfileCache(const std::vector<CharacteristicProfile>& characteristicProfiles);

private:
    std::mutex deviceProfileMutex_;
    // The key is profileKey, the value is DeviceProfile
    std::unordered_map<std::string, DeviceProfile> deviceProfileMap_;
    std::mutex serviceProfileMutex_;
    // The key is profileKey, the value is ServiceProfile
    std::unordered_map<std::string, ServiceProfile> serviceProfileMap_;
    std::mutex charProfileMutex_;
    // The key is profileKey, the value is CharacteristicProfile
    std::unordered_map<std::string, CharacteristicProfile> charProfileMap_;
    std::mutex syncListenerMutex_;
    // The key is procName, the value is syncCallback
    std::map<std::string, sptr<IRemoteObject>> syncListenerMap_;
    sptr<IRemoteObject::DeathRecipient> syncListenerDeathRecipient_ = nullptr;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_CACHE_H
