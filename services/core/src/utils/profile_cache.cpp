/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "profile_cache.h"

#include <algorithm>
#include <cinttypes>

#include "datetime_ex.h"
#include "device_manager.h"

#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_errors.h"
#include "device_profile_manager.h"
#include "profile_utils.h"
#include "static_profile_manager.h"
#include "switch_profile_manager.h"
#include "sync_subscriber_death_recipient.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ProfileCache);

namespace {
    const std::string TAG = "ProfileCache";
}

int32_t ProfileCache::Init()
{
    HILOGI("call!");
    ContentSensorManagerUtils::GetInstance().ObtainDeviceDataSyncMode();
    RefreshProfileCache();
    SwitchProfileManager::GetInstance().RefreshLocalSwitchProfile();
    syncListenerDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new SyncSubscriberDeathRecipient);
    std::vector<DistributedHardware::DmDeviceInfo> allOnlineDeviceInfo;
    int32_t res =
        DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(DP_PKG_NAME, "", allOnlineDeviceInfo);
    if (res != DP_SUCCESS || allOnlineDeviceInfo.empty()) {
        HILOGW("GetTrustedDeviceList failed, res: %{public}d", res);
        return DP_SUCCESS;
    }
<<<<<<< HEAD
    {
        std::lock_guard<std::mutex> lock(foregroundIdMutex_);
        foregroundId_ = GetForegroundId();
        if (foregroundId_ == DP_GET_FOREGROUND_ID_FAIL) {
            LOGE("GetForegroundId id failed, ForegroundId: %{public}d", foregroundId_);
        }
    }
=======
>>>>>>> 8f3393c (删除cache中不必要的代码)

    std::string udid = EMPTY_STRING;
    std::lock_guard<std::mutex> lock(onlineDeviceLock_);
    for (const auto& dmDeviceInfo : allOnlineDeviceInfo) {
        if (!ProfileUtils::GetUdidByNetworkId(dmDeviceInfo.networkId, udid)) {
            HILOGE("get udid by networkId failed, networkId:%{public}s",
                ProfileUtils::GetAnonyString(dmDeviceInfo.networkId).c_str());
            continue;
        }
        onlineDevMap_[udid] = dmDeviceInfo.networkId;
        HILOGI("Init add %{public}s", ProfileUtils::GetAnonyString(udid).c_str());
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::UnInit()
{
    HILOGI("UnInit");
    {
        std::lock_guard<std::mutex> lock(onlineDeviceLock_);
        onlineDevMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(deviceProfileMutex_);
        deviceProfileMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(serviceProfileMutex_);
        serviceProfileMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        charProfileMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(staticCharProfileMutex_);
        staticCharProfileMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        syncListenerMap_.clear();
    }
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
            HILOGE("DeviceProfileMap size is invalid!size: %{public}zu!", deviceProfileMap_.size());
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
            HILOGE("ServiceProfileMap size is invalid!size: %{public}zu!", serviceProfileMap_.size());
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
            HILOGE("CharProfileMap size is invalid!size: %{public}zu!", charProfileMap_.size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        charProfileMap_[charProfileKey] = charProfile;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::AddStaticCharProfile(const CharacteristicProfile& charProfile)
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
        std::lock_guard<std::mutex> lock(staticCharProfileMutex_);
        if (staticCharProfileMap_.size() > MAX_CHAR_SIZE) {
            HILOGE("CharProfileMap size is invalid!size: %{public}zu!", staticCharProfileMap_.size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        staticCharProfileMap_[charProfileKey] = charProfile;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::AddStaticCharProfileBatch(
    const std::unordered_map<std::string, CharacteristicProfile>& charProfiles)
{
    if (charProfiles.size() > MAX_CHAR_SIZE) {
        HILOGE("charProfiles size is too large");
        return DP_INVALID_PARAMS;
    }
    for (const auto& item : charProfiles) {
        HILOGD("%{public}s!", item.second.dump().c_str());
        ProfileCache::AddStaticCharProfile(item.second);
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
            HILOGD("ProfileKey is not found in charProfileMap!");
            return DP_NOT_FOUND_FAIL;
        }
        charProfile = charProfileMap_[charProfileKey];
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetStaticCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& charKey, CharacteristicProfile& charProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(charKey)) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(staticCharProfileMutex_);
        std::string charProfileKey = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, charKey);
        if (staticCharProfileMap_.find(charProfileKey) == staticCharProfileMap_.end()) {
            HILOGI("ProfileKey is not found in charProfileMap!");
            return DP_NOT_FOUND_FAIL;
        }
        charProfile = staticCharProfileMap_[charProfileKey];
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
        return false;
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
        return false;
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
        return false;
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
    std::vector<CharacteristicProfile> charProfiles;
    StaticProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    RefreshCharProfileCache(charProfiles);
    int64_t endTime = GetTickCount();
    HILOGI("spend %{public}" PRId64 " ms", endTime - beginTime);
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

int32_t ProfileCache::RefreshStaticProfileCache(const std::unordered_map<std::string, CharacteristicProfile>&
    staticProfiles)
{
    if (staticProfiles.empty() || staticProfiles.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Params is invalid!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        charProfileMap_.clear();
        for (const auto& staticProfileItem : staticProfiles) {
            HILOGD("profile: %{public}s!", staticProfileItem.second.dump().c_str());
            charProfileMap_[staticProfileItem.first] = staticProfileItem.second;
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
        HILOGI("caller %{public}s!", caller.c_str());
        syncListener->AddDeathRecipient(syncListenerDeathRecipient_);
        syncListenerMap_[caller] = syncListener;
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::GetSyncListeners(std::map<std::string, sptr<IRemoteObject>>& syncListeners)
{
    HILOGD("call!");
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
    HILOGD("call!");
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        auto iter = syncListenerMap_.begin();
        while (iter!= syncListenerMap_.end()) {
            if (syncListeners.count(iter->first) != 0) {
                if (iter->second != nullptr) {
                    iter->second->RemoveDeathRecipient(syncListenerDeathRecipient_);
                }
                HILOGI("caller %{public}s!", iter->first.c_str());
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
    HILOGD("call!");
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
        HILOGI("caller %{public}s!", caller.c_str());
        if (syncListenerMap_[caller] == nullptr) {
            HILOGE("this caller syncListener is nullptr, caller : %{public}s", caller.c_str());
            return DP_NULLPTR;
        }
        syncListenerMap_[caller]->RemoveDeathRecipient(syncListenerDeathRecipient_);
        syncListenerMap_.erase(caller);
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::RemoveSyncListener(sptr<IRemoteObject> syncListener)
{
    HILOGD("call!");
    if (syncListener == nullptr) {
        HILOGE("syncListener is nullptr!");
        return DP_INVALID_PARAMS;
    }
    {
        std::lock_guard<std::mutex> lock(syncListenerMutex_);
        auto iter = std::find_if(syncListenerMap_.begin(), syncListenerMap_.end(), [=](
            const std::pair<std::string, sptr<IRemoteObject>>& item)->bool {
            return item.second == syncListener;
        });
        if (iter == syncListenerMap_.end()) {
            HILOGE("syncListener is not exist!");
            return DP_NOT_FOUND_FAIL;
        }
        HILOGI("remote procName = %{public}s", iter->first.c_str());
        if (iter->second != nullptr) {
            iter->second->RemoveDeathRecipient(syncListenerDeathRecipient_);
        }
        syncListenerMap_.erase(iter);
    }
    return DP_SUCCESS;
}

uint32_t ProfileCache::GetSwitch()
{
    HILOGD("call!");
    std::lock_guard<std::mutex> lock(switchMutex_);
    return curLocalSwitch_;
}

int32_t ProfileCache::SetSwitchByProfileBatch(const std::vector<CharacteristicProfile>& charProfiles,
    const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, uint32_t& outSwitch)
{
    HILOGD("call!");
    if (charProfiles.empty()) {
        HILOGE("charProfiles is empty");
        return DP_INVALID_PARAMS;
    }
    if (charProfiles.size() > MAX_CHAR_SIZE) {
        HILOGE("charProfiles size is to large");
        return DP_INVALID_PARAMS;
    }
    std::lock_guard<std::mutex> lock(switchMutex_);
    outSwitch = curLocalSwitch_;
    for (auto item : charProfiles) {
        if (!IsSwitchValid(item, switchServiceMap, SWITCH_OPERATE_PUT)) {
            HILOGE("SetSwitchByProfileBatch params invalid");
            return DP_INVALID_PARAMS;
        }
        auto service = switchServiceMap.find(item.GetServiceName());
        uint32_t mask = NUM_1U << (static_cast<uint32_t>(service->second));
        uint32_t value = static_cast<uint32_t>(std::stoi(item.GetCharacteristicValue()));
        if (value != 0) {
            outSwitch |= mask;
            HILOGI("service: %{public}s, switch on, currentSwitch: %{public}d",
                ProfileUtils::GetAnonyString(item.GetServiceName()).c_str(), outSwitch);
        } else {
            outSwitch &= ~mask;
            HILOGI("service: %{public}s, switch off, currentSwitch: %{public}d",
                ProfileUtils::GetAnonyString(item.GetServiceName()).c_str(), outSwitch);
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileCache::SetSwitchByProfile(const CharacteristicProfile& charProfile,
    const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, uint32_t& outSwitch)
{
    HILOGD("call!");
    if (!IsSwitchValid(charProfile, switchServiceMap, SWITCH_OPERATE_PUT)) {
        HILOGE("SetSwitch params invalid");
        return DP_INVALID_PARAMS;
    }
    auto service = switchServiceMap.find(charProfile.GetServiceName());
    uint32_t mask = NUM_1U << (static_cast<uint32_t>(service->second));
    uint32_t value = static_cast<uint32_t>(std::stoi(charProfile.GetCharacteristicValue()));
    if (value != 0) {
        outSwitch |= mask;
        HILOGI("SetSwitch service: %{public}s, switch on, currentSwitch: %{public}d",
            ProfileUtils::GetAnonyString(charProfile.GetServiceName()).c_str(), outSwitch);
    } else {
        outSwitch &= ~mask;
        HILOGI("SetSwitch service: %{public}s, switch off, currentSwitch: %{public}d",
            ProfileUtils::GetAnonyString(charProfile.GetServiceName()).c_str(), outSwitch);
    }
    return DP_SUCCESS;
}

bool ProfileCache::IsSwitchValid(const CharacteristicProfile& charProfile,
    const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, const std::string& operate)
{
    HILOGD("call!");
    if (charProfile.GetCharacteristicKey() != SWITCH_STATUS || switchServiceMap.empty()) {
        HILOGE("params invalid");
        return false;
    }
    //Verify and intercept the input switch key and value.
    if (operate == SWITCH_OPERATE_PUT) {
        if (charProfile.GetCharacteristicValue().empty() ||
            (charProfile.GetCharacteristicValue() != SWITCH_OFF &&
                charProfile.GetCharacteristicValue() != SWITCH_ON)) {
            HILOGE("params invalid");
            return false;
        }
    }
    if (switchServiceMap.find(charProfile.GetServiceName()) == switchServiceMap.end()) {
        HILOGE("can not find switchServiceName : %{public}s", charProfile.GetServiceName().c_str());
        return false;
    }
    return true;
}

int32_t ProfileCache::SetSwitchProfile(CharacteristicProfile& charProfile, uint32_t switchValue)
{
    HILOGD("call!");
    if (!IsSwitchValid(charProfile, SWITCH_SERVICE_MAP, SWITCH_OPERATE_GET)) {
        HILOGE("SetSwitchProfile params invalid");
        return DP_INVALID_PARAMS;
    }
    auto service = SWITCH_SERVICE_MAP.find(charProfile.GetServiceName());
    uint32_t mask = NUM_1U << static_cast<int32_t>(service->second);
    charProfile.SetCharacteristicValue(std::to_string((((switchValue & mask) >>
        (static_cast<int32_t>(service->second))))));
    if (charProfile.GetDeviceId() == GetLocalUdid()) {
        std::lock_guard<std::mutex> lock(switchMutex_);
        curLocalSwitch_ = switchValue;
    }
    return DP_SUCCESS;
}

void ProfileCache::SetCurSwitch(uint32_t newSwitch)
{
    std::lock_guard<std::mutex> lock(switchMutex_);
    curLocalSwitch_ = newSwitch;
    return;
}

void ProfileCache::OnNodeOnline(const std::string& peerNetworkId)
{
    HILOGD("call! peerNetworkId=%{public}s", ProfileUtils::GetAnonyString(peerNetworkId).c_str());
    std::string udid = EMPTY_STRING;
    if (!ProfileUtils::GetUdidByNetworkId(peerNetworkId, udid)) {
        HILOGE("get udid by networkId failed");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(onlineDeviceLock_);
        onlineDevMap_[udid] = peerNetworkId;
        HILOGI("add %{public}s", ProfileUtils::GetAnonyString(udid).c_str());
    }
}

void ProfileCache::OnNodeOffline(const std::string& peerNetworkId)
{
    HILOGD("call! peerNetworkId=%{public}s", ProfileUtils::GetAnonyString(peerNetworkId).c_str());
    std::string udid = EMPTY_STRING;
    if (!ProfileUtils::GetUdidByNetworkId(peerNetworkId, udid)) {
        HILOGE("get udid by networkId failed");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(onlineDeviceLock_);
        onlineDevMap_.erase(udid);
        HILOGI("release %{public}s", ProfileUtils::GetAnonyString(udid).c_str());
    }
}

bool ProfileCache::IsLocalOrOnlineDevice(const std::string& deviceId)
{
    if (deviceId == GetLocalUdid()) {
        HILOGI("%{public}s is localDevice", ProfileUtils::GetAnonyString(deviceId).c_str());
        return true;
    }
    std::lock_guard<std::mutex> lock(onlineDeviceLock_);
    if (onlineDevMap_.find(deviceId) != onlineDevMap_.end()) {
        HILOGI("%{public}s is online", ProfileUtils::GetAnonyString(deviceId).c_str());
        return true;
    }
    HILOGE("%{public}s is offline or is not a local device.", ProfileUtils::GetAnonyString(deviceId).c_str());
    return false;
}

int32_t ProfileCache::GetNetWorkIdByUdid(const std::string& udid, std::string& networkId)
{
    HILOGD("call!");
    if (udid.empty()) {
        HILOGE("UDID is empty");
        return DP_INVALID_PARAMS;
    }
    
    if (udid == GetLocalUdid()) {
        networkId = GetLocalNetworkId();
        HILOGI("success, networkId is localNetworkid: %{public}s",
            ProfileUtils::GetAnonyString(networkId).c_str());
        return DP_SUCCESS;
    }
    std::lock_guard<std::mutex> lock(onlineDeviceLock_);
    if (onlineDevMap_.find(udid) == onlineDevMap_.end()) {
        HILOGE("GetNetWorkIdByUdid failed");
        return DP_GET_NETWORKID_BY_UDID_FAIL;
    }
    networkId = onlineDevMap_[udid];
    HILOGI("success, networkId: %{public}s", ProfileUtils::GetAnonyString(networkId).c_str());
    return DP_SUCCESS;
}

int32_t ProfileCache::GetUdidByNetWorkId(const std::string& networkId, std::string& udid)
{
    if (networkId.empty()) {
        HILOGE("networkId is empty");
        return DP_INVALID_PARAMS;
    }
    if (GetLocalNetworkId() == networkId) {
        udid = GetLocalUdid();
        HILOGD("networkId is local");
        return DP_SUCCESS;
    }
    std::lock_guard<std::mutex> lock(onlineDeviceLock_);
    for (auto& item : onlineDevMap_) {
        if (item.second == networkId) {
            udid = item.first;
            HILOGI("find udid: %{public}s", ProfileUtils::GetAnonyString(udid).c_str());
            return DP_SUCCESS;
        }
    }
    if (!ProfileUtils::GetUdidByNetworkId(networkId, udid)) {
        HILOGE("GetUdidByNetworkId failed");
        return DP_GET_UDID_BY_NETWORKID_FAIL;
    }
    onlineDevMap_[udid] = networkId;
    return DP_SUCCESS;
}

int32_t ProfileCache::GetServiceNameByPos(int32_t pos,
    const std::unordered_map<std::string, SwitchFlag>& switchServiceMap, std::string& serviceName)
{
    if (pos <= (int32_t)SwitchFlag::SWITCH_FLAG_MIN || pos >= (int32_t)SwitchFlag::SWITCH_FLAG_MAX ||
        switchServiceMap.empty()) {
        HILOGE("params are invalid");
        return DP_INVALID_PARAMS;
    }
    if (switchServiceMap.size() > MAX_SERVICE_SIZE) {
        HILOGE("switchServiceMap size is too large");
        return DP_INVALID_PARAMS;
    }
    for (const auto& item : switchServiceMap) {
        if (item.second == (SwitchFlag)pos) {
            serviceName = item.first;
            HILOGI("find serviceName: %{public}s", serviceName.c_str());
            return DP_SUCCESS;
        }
    }
    HILOGE("GetServiceNameByPos failed");
    return DP_GET_SERVICENAME_BY_POS_FAIL;
}

int32_t ProfileCache::GetSwitchProfilesByServiceName(const std::string& charProfileKey,
    CharacteristicProfile& switchProfile)
{
    if (charProfileKey.empty()) {
        HILOGE("params are invalid");
        return DP_INVALID_PARAMS;
    }

    std::lock_guard<std::mutex> lock(charProfileMutex_);
    if (charProfileMap_.find(charProfileKey) == charProfileMap_.end()) {
        HILOGW("ProfileKey is not found in charProfileMap!");
    }

    switchProfile = charProfileMap_[charProfileKey];
    return DP_SUCCESS;
}

bool ProfileCache::IsCharProfileKeyExist(const std::string& charKey)
{
    if (charKey.empty()) {
        HILOGE("Params is invalid!");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(charProfileMutex_);
        if (charProfileMap_.find(charKey) == charProfileMap_.end()) {
            HILOGI("charKey is not found in charProfileMap!");
            return false;
        }
    }
    return true;
}

std::string ProfileCache::GetLocalUdid()
{
    return ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
}

std::string ProfileCache::GetLocalNetworkId()
{
    DistributedHardware::DmDeviceInfo localDevInfo;
    int32_t res = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(DP_PKG_NAME, localDevInfo);
    if (res != DP_SUCCESS) {
        HILOGE("GetLocalDeviceInfo fail, res: %{public}d.", res);
        return EMPTY_STRING;
    }
    localNetworkId_ = localDevInfo.networkId;
    return localNetworkId_;
}

std::string ProfileCache::GetLocalUuid()
{
    std::string localUuid = EMPTY_STRING;
    std::lock_guard<std::mutex> lock(localUuidMtx_);
    if (!localUuid_.empty()) {
        return localUuid_;
    }
    auto networkId = GetLocalNetworkId();
    if (networkId.empty()) {
        HILOGE("networkId is empty");
        return EMPTY_STRING;
    }
    if (!ProfileUtils::GetUuidByNetworkId(networkId, localUuid) || localUuid.empty()) {
        HILOGE("GetUuidByNetworkId fail");
        return EMPTY_STRING;
    }
    localUuid_ = localUuid;
    return localUuid;
}
<<<<<<< HEAD

int32_t ProfileCache::GetForegroundId()
{
    int32_t foregroundId;
    int32_t res = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundId);
    if (res != DP_SUCCESS) {
        LOGE("GetForegroundId failed, res:%{public}d", res);
        return DP_GET_FOREGROUND_ID_FAIL;
    }
    LOGI("current foregroundId = %{public}d", foregroundId);
    return foregroundId; 
}

=======
>>>>>>> 8f3393c (删除cache中不必要的代码)
} // namespace DeviceProfile
} // namespace OHOS
