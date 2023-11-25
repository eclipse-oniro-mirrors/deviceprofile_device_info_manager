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

#include <cinttypes>
#include <algorithm>
#include "datetime_ex.h"

#include "profile_cache.h"
#include "profile_utils.h"
#include "device_profile_manager.h"
#include "sync_subscriber_death_recipient.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ProfileCache);

namespace {
    const std::string TAG = "ProfileCache";
}

int32_t ProfileCache::Init()
{
    HILOGI("Init");
    RefreshProfileCache();
    syncListenerDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new SyncSubscriberDeathRecipient);
    return DP_SUCCESS;
}

int32_t ProfileCache::UnInit()
{
    HILOGI("UnInit");
    return DP_SUCCESS;
}

int32_t ProfileCache::AddDeviceProfile(const DeviceProfile& deviceProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceProfile.GetDeviceId())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string deviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(deviceProfile.GetDeviceId());
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        if (deviceProfileMap_.size() > MAX_DEVICE_SIZE) {
            HILOGE("DeviceProfileMap size is invalid!");
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        deviceProfileMap_[deviceProfileKey] = deviceProfile;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::AddServiceProfile(const ServiceProfile& serviceProfile)
{
    if (!ProfileUtils::IsKeyValid(serviceProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(serviceProfile.GetServiceName())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string serviceProfileKey = ProfileUtils::GenerateServiceProfileKey(serviceProfile.GetDeviceId(),
        serviceProfile.GetServiceName());
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        if (serviceProfileMap_.size() > MAX_SERVICE_SIZE) {
            HILOGE("ServiceProfileMap size is invalid!");
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        serviceProfileMap_[serviceProfileKey] = serviceProfile;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::AddCharProfile(const CharacteristicProfile& charProfile)
{
    if (!ProfileUtils::IsKeyValid(charProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetServiceName()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetCharacteristicKey())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(charProfile.GetDeviceId(),
        charProfile.GetServiceName(), charProfile.GetCharacteristicKey());
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        if (charProfileMap_.size() > MAX_CHAR_SIZE) {
            HILOGE("CharProfileMap size is invalid!");
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        charProfileMap_[charProfileKey] = charProfile;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceId)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        std::string deviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(deviceId);
        if (deviceProfileMap_.find(deviceProfileKey) == deviceProfileMap_.end()) {
            HILOGI("ProfileKey is not found in deviceProfileMap!");
            return DP_NOT_FOUND_FAIL;
        }
        deviceProfile = deviceProfileMap_[deviceProfileKey];
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        std::string serviceProfileKey = ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
        if (serviceProfileMap_.find(serviceProfileKey) == serviceProfileMap_.end()) {
            HILOGI("ProfileKey is not found in serviceProfileMap!");
            return DP_NOT_FOUND_FAIL;
        }
        serviceProfile = serviceProfileMap_[serviceProfileKey];
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& charKey, CharacteristicProfile& charProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(charKey)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
        if (charProfileMap_.find(charProfileKey) == charProfileMap_.end()) {
            HILOGI("ProfileKey is not found in charProfileMap!");
            return DP_NOT_FOUND_FAIL;
        }
        charProfile = charProfileMap_[charProfileKey];
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::DeleteDeviceProfile(const std::string& deviceId)
{
    if (!ProfileUtils::IsKeyValid(deviceId)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string deviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(deviceId);
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        deviceProfileMap_.erase(deviceProfileKey);
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string serviceProfileKey = ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        serviceProfileMap_.erase(serviceProfileKey);
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::DeleteCharProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& charKey)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(charKey)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        charProfileMap_.erase(charProfileKey);
    }
    return DP_SUCCESS;
}

bool ProfileCache::IsDeviceProfileExist(const DeviceProfile& deviceProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceProfile.GetDeviceId())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string deviceProfileKey = ProfileUtils::GenerateDeviceProfileKey(deviceProfile.GetDeviceId());
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        if (deviceProfileMap_.find(deviceProfileKey) == deviceProfileMap_.end()) {
            HILOGE("ProfileKey is not found in deviceProfileMap!");
            return false;
        }
        DeviceProfile deviceProfileCache = deviceProfileMap_[deviceProfileKey];
        if (deviceProfile != deviceProfileCache) {
            HILOGE("The device profile is not same in cache!");
            return false;
        }
    }
    return true;
}

bool ProfileCache::IsServiceProfileExist(const ServiceProfile& serviceProfile)
{
    if (!ProfileUtils::IsKeyValid(serviceProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(serviceProfile.GetServiceName())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string serviceProfileKey = ProfileUtils::GenerateServiceProfileKey(serviceProfile.GetDeviceId(),
        serviceProfile.GetServiceName());
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        if (serviceProfileMap_.find(serviceProfileKey) == serviceProfileMap_.end()) {
            HILOGE("ProfileKey is not found in serviceProfileMap!");
            return false;
        }
        ServiceProfile serviceProfileCache = serviceProfileMap_[serviceProfileKey];
        if (serviceProfile != serviceProfileCache) {
            HILOGE("The service profile is not same in cache!");
            return false;
        }
    }
    return true;
}

bool ProfileCache::IsCharProfileExist(const CharacteristicProfile& charProfile)
{
    if (!ProfileUtils::IsKeyValid(charProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetServiceName()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetCharacteristicKey())) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(charProfile.GetDeviceId(),
        charProfile.GetServiceName(), charProfile.GetCharacteristicKey());
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        if (charProfileMap_.find(charProfileKey) == charProfileMap_.end()) {
            HILOGI("ProfileKey is not found in charProfileMap!");
            return false;
        }
        CharacteristicProfile charProfileCache = charProfileMap_[charProfileKey];
        if (charProfile != charProfileCache) {
            HILOGI("The char profile is not same in cache!");
            return false;
        }
    }
    return true;
}

int32_t ProfileCache::RefreshProfileCache()
{
    int64_t beginTime = GetTickCount();
    std::vector<DeviceProfile> deviceProfiles;
    DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    RefreshDeviceProfileCache(deviceProfiles);
    std::vector<ServiceProfile> serviceProfiles;
    DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    RefreshServiceProfileCache(serviceProfiles);
    std::vector<CharacteristicProfile> charProfiles;
    DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    RefreshCharProfileCache(charProfiles);
    int64_t endTime = GetTickCount();
    HILOGI("RefreshProfileCache, spend %{public}" PRId64 " ms", endTime - beginTime);
    return DP_SUCCESS;
}

int32_t ProfileCache::RefreshDeviceProfileCache(const std::vector<DeviceProfile>& deviceProfiles)
{
    if (deviceProfiles.empty() || deviceProfiles.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        deviceProfileMap_.clear();
        for (const auto& deviceProfile : deviceProfiles) {
            std::string profileKey = ProfileUtils::GenerateDeviceProfileKey(deviceProfile.GetDeviceId());
            deviceProfileMap_[profileKey] = deviceProfile;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RefreshServiceProfileCache(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (serviceProfiles.empty() || serviceProfiles.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        serviceProfileMap_.clear();
        for (const auto& serviceProfile : serviceProfiles) {
            std::string profileKey = ProfileUtils::GenerateServiceProfileKey(serviceProfile.GetDeviceId(),
                serviceProfile.GetServiceName());
            serviceProfileMap_[profileKey] = serviceProfile;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RefreshCharProfileCache(const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    if (characteristicProfiles.empty() || characteristicProfiles.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        charProfileMap_.clear();
        for (const auto& charProfile : characteristicProfiles) {
            std::string profileKey = ProfileUtils::GenerateCharProfileKey(charProfile.GetDeviceId(),
                charProfile.GetServiceName(), charProfile.GetCharacteristicKey());
            charProfileMap_[profileKey] = charProfile;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::AddSyncListener(const std::string& caller, sptr<IRemoteObject> syncListener)
{
    if (caller.empty() || caller.size() > MAX_STRING_LEN || syncListener == nullptr) {
        HILOGE("params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        if (syncListenerMap_.size() > MAX_LISTENER_SIZE) {
            HILOGE("syncListenerMap is exceed max listenerSize!");
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        HILOGI("AddSyncListener caller %s!", caller.c_str());
        syncListener->AddDeathRecipient(syncListenerDeathRecipient_);
        syncListenerMap_[caller] = syncListener;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetSyncListeners(std::map<std::string, sptr<IRemoteObject>>& syncListeners)
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        for (const auto& item : syncListenerMap_) {
            syncListeners[item.first] = item.second;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RemoveSyncListeners(std::map<std::string, sptr<IRemoteObject>> syncListeners)
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        auto iter = syncListenerMap_.begin();
        while (iter!= syncListenerMap_.end()) {
            if (syncListeners.count(iter->first) != 0) {
                if (iter->second != nullptr) {
                    iter->second->RemoveDeathRecipient(syncListenerDeathRecipient_);
                }
                HILOGI("RemoveSyncListener caller %s!", iter->first.c_str());
                iter = syncListenerMap_.erase(iter);
            } else {
                iter++;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RemoveSyncListener(const std::string& caller)
{
    if (caller.empty() || caller.size() > MAX_STRING_LEN) {
        HILOGE("descriptor is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        if (syncListenerMap_.count(caller) == 0) {
            HILOGE("Can not find this listener!");
            return DP_NOT_FOUND_FAIL;
        }
        HILOGI("RemoveSyncListener caller %s!", caller.c_str());
        syncListenerMap_[caller]->RemoveDeathRecipient(syncListenerDeathRecipient_);
        syncListenerMap_.erase(caller);
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RemoveSyncListener(sptr<IRemoteObject> syncListener)
{
    if (syncListener == nullptr) {
        HILOGE("syncListener is nullptr!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        auto iter = std::find_if(syncListenerMap_.begin(), syncListenerMap_.end(), [&](
            const std::pair<std::string, sptr<IRemoteObject>> &item)->bool {
            return item.second == syncListener;
        });
        if (iter == syncListenerMap_.end()) {
            HILOGE("syncListener is not exist!");
            return DP_NOT_FOUND_FAIL;
        }
        DHLOGI("RemoveSyncListener remote procName = %{public}s", iter->first.c_str());
        if (iter->second != nullptr) {
            iter->second->RemoveDeathRecipient(syncListenerDeathRecipient_);
        }
        syncListenerMap_.erase(iter);
    }
}
} // namespace DeviceProfile
} // namespace OHOS