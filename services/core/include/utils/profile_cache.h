/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <mutex>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "iremote_object.h"
#include "single_instance.h"

#include "characteristic_profile.h"
#include "device_profile.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "dp_subscribe_info.h"
#include "profile_utils.h"
#include "service_profile.h"
#include "trusted_device_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileCache {
    DECLARE_SINGLE_INSTANCE(ProfileCache);

public:
    int32_t Init();
    int32_t UnInit();
    // local dynamic DeviceProfile
    int32_t AddDeviceProfile(const DeviceProfile& deviceProfile);
    // local dynamic ServiceProfile
    int32_t AddServiceProfile(const ServiceProfile& serviceProfile);
    // all static meta CharProfile 、 all switch CharProfile 、 local dynamic CharProfile
    int32_t AddCharProfile(const CharacteristicProfile& charProfile);
    // all static CharProfile
    int32_t AddStaticCharProfile(const CharacteristicProfile& charProfile);
    int32_t AddStaticCharProfileBatch(const std::unordered_map<std::string, CharacteristicProfile>& charProfiles);
    uint32_t GetSwitch();
    int32_t GetNetWorkIdByUdid(const std::string& udid, std::string& networkId);
    int32_t GetUdidByNetWorkId(const std::string& networkId, std::string& udid);
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile);
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& charKey, CharacteristicProfile& charProfile);
    int32_t GetStaticCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
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
    int32_t SetSwitchByProfileBatch(const std::vector<CharacteristicProfile>& charProfiles,
        const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, uint32_t& outSwitch);
    int32_t SetSwitchByProfile(const CharacteristicProfile& charProfile,
        const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, uint32_t& outSwitch);
    bool IsSwitchValid(const CharacteristicProfile& charProfile,
        const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, const std::string& operate);
    int32_t SetSwitchProfile(CharacteristicProfile& charProfile, uint32_t switchValue);
    void OnNodeOnline(const TrustedDeviceInfo& trustedDeviceInfo);
    void OnNodeOffline(const std::string& peerNetworkId);
    void SetCurSwitch(uint32_t newSwitch);
    int32_t GetServiceNameByPos(int32_t pos, const std::unordered_map<std::string, SwitchFlag>& switchServiceMap,
        std::string& serviceName);
    int32_t GetSwitchProfilesByServiceName(const std::string& charProfileKey, CharacteristicProfile& switchProfile);
    bool IsCharProfileKeyExist(const std::string& charKey);
    std::string GetLocalUdid();
    std::string GetLocalNetworkId();
    std::string GetLocalUuid();
    std::string GetLocalAccountId();
    int32_t AddAllTrustedDevices(const std::vector<TrustedDeviceInfo>& deviceInfos);
    bool FilterAndGroupOnlineDevices(const std::vector<std::string>& deviceList,
        std::vector<std::string>& ohBasedDevices,
        std::vector<std::tuple<std::string, std::string, bool>>& notOHBasedDevices);
    bool IsDeviceOnline();

private:
    int32_t RefreshCharProfileCache(const std::vector<CharacteristicProfile>& characteristicProfiles);
    int32_t RefreshStaticProfileCache(const std::unordered_map<std::string, CharacteristicProfile>& staticProfiles);

private:
    std::string localNetworkId_;
    std::mutex switchMutex_;
    uint32_t curLocalSwitch_ = 0x0000;
    std::mutex onlineDeviceLock_;
    std::unordered_map<std::string, TrustedDeviceInfo> onlineDevMap_;
    std::mutex deviceProfileMutex_;
    // The key is profileKey, the value is DeviceProfile
    std::unordered_map<std::string, DeviceProfile> deviceProfileMap_;
    std::mutex serviceProfileMutex_;
    // The key is profileKey, the value is ServiceProfile
    std::unordered_map<std::string, ServiceProfile> serviceProfileMap_;
    std::mutex charProfileMutex_;
    // The key is profileKey, the value is CharacteristicProfile
    std::unordered_map<std::string, CharacteristicProfile> charProfileMap_;
    std::mutex staticCharProfileMutex_;
    // The key is profileKey, the value is CharacteristicProfile
    std::unordered_map<std::string, CharacteristicProfile> staticCharProfileMap_;
    std::mutex syncListenerMutex_;
    // The key is procName, the value is syncCallback
    std::map<std::string, sptr<IRemoteObject>> syncListenerMap_;
    sptr<IRemoteObject::DeathRecipient> syncListenerDeathRecipient_ = nullptr;
    std::mutex localUuidMtx_;
    std::string localUuid_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_CACHE_H
