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

#include "profile_control_utils.h"

#include <mutex>
#include <memory>
#include <algorithm>
#include <dlfcn.h>
#include <vector>
#include <list>

#include "kv_adapter.h"
#include "device_manager.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "permission_manager.h"
#include "switch_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ProfileControlUtils";
}
int32_t ProfileControlUtils::PutDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const DeviceProfile& deviceProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceProfile.GetDeviceId())) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("PutDeviceProfile, deviceId: %s!", ProfileUtils::GetAnonyString(deviceProfile.GetDeviceId()).c_str());
    if (ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile)) {
        HILOGI("the profile is exist!");
        return DP_CACHE_EXIST;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::DeviceProfileToEntries(deviceProfile, entries);
    if (kvStore->PutBatch(entries) != DP_SUCCESS) {
        HILOGE("PutDeviceProfile fail!");
        return DP_PUT_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutServiceProfile(std::shared_ptr<IKVAdapter> kvStore,
    const ServiceProfile& serviceProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(serviceProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(serviceProfile.GetServiceName())) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("PutServiceProfile, deviceId: %s, serviceName: %s!",
        ProfileUtils::GetAnonyString(serviceProfile.GetDeviceId()).c_str(), serviceProfile.GetServiceName().c_str());
    if (ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile)) {
        HILOGW("the profile is exist!");
        return DP_CACHE_EXIST;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
    if (kvStore->PutBatch(entries) != DP_SUCCESS) {
        HILOGE("PutServiceProfile fail!");
        return DP_PUT_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutServiceProfileBatch(std::shared_ptr<IKVAdapter> kvStore,
    const std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (serviceProfiles.empty()) {
        HILOGE("serviceProfiles is empty!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    for (const auto& serviceProfile : serviceProfiles) {
        if (!ProfileUtils::IsKeyValid(serviceProfile.GetDeviceId()) ||
            !ProfileUtils::IsKeyValid(serviceProfile.GetServiceName())) {
            HILOGE("the profile is invalid!");
            return DP_INVALID_PARAMS;
        }
        HILOGI("PutServiceProfile, deviceId: %s, serviceName: %s!", ProfileUtils::GetAnonyString(
            serviceProfile.GetDeviceId()).c_str(), serviceProfile.GetServiceName().c_str());
        if (ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile)) {
            HILOGW("the profile is exist!");
            return DP_CACHE_EXIST;
        }
        ProfileUtils::ServiceProfileToEntries(serviceProfile, entries);
        ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    }
    if (kvStore->PutBatch(entries) != DP_SUCCESS) {
        HILOGE("PutServiceProfile fail!");
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
    const CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(charProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetServiceName()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetCharacteristicKey())) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("PutCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
        ProfileUtils::GetAnonyString(charProfile.GetDeviceId()).c_str(), charProfile.GetServiceName().c_str(),
        charProfile.GetCharacteristicKey().c_str());
    if (ProfileCache::GetInstance().IsCharProfileExist(charProfile)) {
        HILOGW("the profile is exist!");
        return DP_CACHE_EXIST;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::CharacteristicProfileToEntries(charProfile, entries);
    if (kvStore->PutBatch(entries) != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfile fail!");
        return DP_PUT_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutSwitchCharacteristicProfile(const std::string& appId,
    const CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    if (!ProfileUtils::IsKeyValid(charProfile.GetDeviceId()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetServiceName()) ||
        !ProfileUtils::IsKeyValid(charProfile.GetCharacteristicKey() ||
        appId.empty())) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("PutCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
        ProfileUtils::GetAnonyString(charProfile.GetDeviceId()).c_str(), charProfile.GetServiceName().c_str(),
        charProfile.GetCharacteristicKey().c_str());
    if (ProfileCache::GetInstance().IsCharProfileExist(charProfile)) {
        HILOGW("the profile is exist!");
        return DP_CACHE_EXIST;
    }
    uint32_t curSwitch = ProfileCache::GetInstance().GetSwitch();
    HILOGD("PutSwitchCharacteristicProfile curSwitch:%d", curSwitch);
    uint32_t newSwitch = curSwitch;
    int32_t res = ProfileCache::GetInstance().SetSwitchByProfile(charProfile, SWITCH_SERVICE_MAP, newSwitch);
    if (res != DP_SUCCESS) {
        HILOGE("set switch profile failed: %d", res);
        return res;
    }
    HILOGD("PutSwitchCharacteristicProfile newSwitch:%d", newSwitch);
    res = SwitchAdapter::GetInstance().PutSwitch(appId, newSwitch, NUM_24U);
    if (res != DP_SUCCESS) {
        HILOGE("put switch failed: %d", res);
        return res;
    }
    ProfileCache::GetInstance().SetCurSwitch(newSwitch);
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutSwitchCharacteristicProfileBatch(const std::string& appId,
    const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    if (charProfiles.empty() || appId.empty()) {
        HILOGE("charProfiles or addid are empty");
        return DP_INVALID_PARAMS;
    }
    int32_t res = 0;
    uint32_t curSwitch = ProfileCache::GetInstance().GetSwitch();
    HILOGD("PutSwitchCharacteristicProfileBatch curSwitch:%d", curSwitch);
    uint32_t newSwitch = curSwitch;
    for (auto item : charProfiles) {
        if (!ProfileUtils::IsKeyValid(item.GetDeviceId()) ||
            !ProfileUtils::IsKeyValid(item.GetServiceName()) ||
            !ProfileUtils::IsKeyValid(item.GetCharacteristicKey())) {
            HILOGE("a profile is invalid! serviceName: %s", item.GetServiceName().c_str());
            return DP_INVALID_PARAMS;
        }
        if (ProfileCache::GetInstance().IsCharProfileExist(item)) {
            HILOGW("this profile is exist!");
            continue;
        }
        HILOGI("PutCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
            ProfileUtils::GetAnonyString(item.GetDeviceId()).c_str(), item.GetServiceName().c_str(),
            item.GetCharacteristicKey().c_str());
        res = ProfileCache::GetInstance().SetSwitchByProfile(item, SWITCH_SERVICE_MAP, newSwitch);
        if (res != DP_SUCCESS) {
            HILOGE("set switch profile failed: %d", res);
            return res;
        }
    }
    HILOGD("PutSwitchCharacteristicProfileBatch newSwitch:%d", newSwitch);
    res = SwitchAdapter::GetInstance().PutSwitch(appId, newSwitch, NUM_24U);
    if (res != DP_SUCCESS) {
        HILOGE("put switch Batch failed: %d", res);
        return res;
    }
    ProfileCache::GetInstance().SetCurSwitch(newSwitch);
    for (auto item : charProfiles) {
        ProfileCache::GetInstance().AddCharProfile(item);
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutCharacteristicProfileBatch(std::shared_ptr<IKVAdapter> kvStore,
    const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (charProfiles.empty()) {
        HILOGE("charProfiles is empty!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    for (const auto& charProfile : charProfiles) {
        if (!ProfileUtils::IsKeyValid(charProfile.GetDeviceId()) ||
            !ProfileUtils::IsKeyValid(charProfile.GetServiceName()) ||
            !ProfileUtils::IsKeyValid(charProfile.GetCharacteristicKey())) {
            HILOGE("the profile is invalid!");
            continue;
        }
        HILOGI("PutCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
            ProfileUtils::GetAnonyString(charProfile.GetDeviceId()).c_str(), charProfile.GetServiceName().c_str(),
            charProfile.GetCharacteristicKey().c_str());
        if (ProfileCache::GetInstance().IsCharProfileExist(charProfile)) {
            HILOGW("the profile is exist!");
            continue;
        }
        ProfileUtils::CharacteristicProfileToEntries(charProfile, entries);
        ProfileCache::GetInstance().AddCharProfile(charProfile);
    }
    if (kvStore->PutBatch(entries) != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfile fail!");
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    DeviceProfile& deviceProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileCache::GetInstance().IsLocalOrOnlineDevice(deviceId)) {
        HILOGE("the profile is offline or is not a local device.");
        return DP_INVALID_PARAMS;
    }
    HILOGI("GetDeviceProfile, deviceId: %s!", ProfileUtils::GetAnonyString(deviceId).c_str());
    if (ProfileCache::GetInstance().GetDeviceProfile(deviceId, deviceProfile) == DP_SUCCESS) {
        HILOGI("GetDeviceProfile in cache!");
        return DP_SUCCESS;
    }
    std::string dbKeyPrefix = ProfileUtils::GenerateDeviceProfileKey(deviceId);
    std::map<std::string, std::string> values;
    if (kvStore->GetByPrefix(dbKeyPrefix, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    HILOGI("GetDeviceProfile in db!");
    ProfileUtils::EntriesToDeviceProfile(values, deviceProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileCache::GetInstance().IsLocalOrOnlineDevice(deviceId)) {
        HILOGE("the profile is offline or is not a local device.");
        return DP_INVALID_PARAMS;
    }
    HILOGI("PutDeviceProfile, deviceId: %s, serviceName: %s!", ProfileUtils::GetAnonyString(deviceId).c_str(),
        serviceName.c_str());
    if (ProfileCache::GetInstance().GetServiceProfile(deviceId, serviceName, serviceProfile) == DP_SUCCESS) {
        HILOGI("GetServiceProfile in cache!");
        return DP_SUCCESS;
    }
    std::string dbKeyPrefix = ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
    std::map<std::string, std::string> values;
    if (kvStore->GetByPrefix(dbKeyPrefix, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    HILOGI("GetServiceProfile in db!");
    ProfileUtils::EntriesToServiceProfile(values, serviceProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileCache::GetInstance().IsLocalOrOnlineDevice(deviceId)) {
        HILOGE("the profile is offline or is not a local device.");
        return DP_INVALID_PARAMS;
    }
    HILOGI("GetCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    if (ProfileCache::GetInstance().GetCharacteristicProfile(deviceId, serviceName, characteristicKey, charProfile)
        == DP_SUCCESS) {
        HILOGI("GetCharProfile in cache!");
        return DP_SUCCESS;
    }
    std::string profileKeyPrefix = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, characteristicKey);
    std::map<std::string, std::string> values;
    if (kvStore->GetByPrefix(profileKeyPrefix, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    ProfileUtils::EntriesToCharProfile(values, charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::RefreshLocalSwitchProfile(const std::string& appId)
{
    HILOGI("call!");
    std::string localNetwork = ProfileCache::GetInstance().GetLocalNetworkId();
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    if (localNetwork.empty() || localUdid.empty() || appId.empty()) {
        HILOGE("params are empty");
        return DP_INVALID_PARAMS;
    }
    uint32_t newSwitch;
    int32_t res = SwitchAdapter::GetInstance().GetSwitch(appId, localNetwork, newSwitch);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitch failed, res: %d", res);
        return DP_GET_KV_DB_FAIL;
    }
    for (int32_t i = SWITCH_FLAG_MIN + NUM_1U; i < SWITCH_FLAG_MAX; ++i) {
        std::string itemSwitchValue = std::to_string((newSwitch >> i) & NUM_1);
        std::string serviceName;
        int32_t res = ProfileCache::GetInstance().GetServiceNameByPos(i, SWITCH_SERVICE_MAP, serviceName);
        if (res != DP_SUCCESS || serviceName.empty()) {
            HILOGE("GetServiceNameByPos failed, serviceName: %s", serviceName.c_str());
            continue;
        }
        const CharacteristicProfile newSwitchProfile = {localUdid, serviceName, SWITCH_STATUS, itemSwitchValue};
        ProfileCache::GetInstance().AddCharProfile(newSwitchProfile);
    }
    ProfileCache::GetInstance().SetCurSwitch(newSwitch);
    HILOGI("update curLocalSwitch: %d", ProfileCache::GetInstance().GetSwitch());
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetSwitchCharacteristicProfile(const std::string& appId, const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey) || appId.empty()) {
        HILOGE("params are invalid!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileCache::GetInstance().IsLocalOrOnlineDevice(deviceId)) {
        HILOGE("the profile is offline or is not a local device.");
        return DP_INVALID_PARAMS;
    }
    HILOGI("GetCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    if (ProfileCache::GetInstance().GetCharacteristicProfile(deviceId, serviceName, characteristicKey, charProfile)
        == DP_SUCCESS) {
        HILOGI("GetCharProfile in cache!");
        return DP_SUCCESS;
    }
    const CharacteristicProfile profile(deviceId, serviceName, characteristicKey, "");
    if (!ProfileCache::GetInstance().IsSwitchValid(profile, SWITCH_SERVICE_MAP, SWITCH_OPERATE_GET)) {
        HILOGE("GetSwitchCharacteristicProfile params invalid");
        return DP_INVALID_PARAMS;
    }
    std::string netWorkId;
    int32_t res = ProfileCache::GetInstance().GetNetWorkIdByUdid(deviceId, netWorkId);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitchCharacteristicProfile GetNetWorkIdByUdid failed, res: %d", res);
        return DP_GET_KV_DB_FAIL;
    }
    uint32_t switchValue;
    res = SwitchAdapter::GetInstance().GetSwitch(appId, netWorkId, switchValue);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitchCharacteristicProfile GetSwitch failed, res: %d", res);
        return DP_GET_KV_DB_FAIL;
    }
    HILOGD("GetSwitchCharacteristicProfile GetSwitch success, switchValue: %d", switchValue);
    charProfile.SetDeviceId(deviceId);
    charProfile.SetServiceName(serviceName);
    charProfile.SetCharacteristicKey(characteristicKey);
    res = ProfileCache::GetInstance().SetSwitchProfile(charProfile, switchValue);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitchCharacteristicProfile SetSwitchProfile failed, res: %d", res);
        return DP_GET_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::DeleteServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("DeleteServiceProfile, deviceId: %s, serviceName: %s!", ProfileUtils::GetAnonyString(deviceId).c_str(),
        serviceName.c_str());

    std::string profileKeyPrefix = ProfileUtils::GenerateServiceProfileKey(deviceId, serviceName);
    if (kvStore->DeleteByPrefix(profileKeyPrefix) != DP_SUCCESS) {
        HILOGE("DeleteServiceProfile fail!");
        return DP_DEL_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::DeleteCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
    const std::string& deviceId, const std::string& serviceName, const std::string& characteristicKey)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("DeleteCharacteristicProfile, deviceId: %s, serviceName: %s, charKey: %s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    std::string profileKeyPrefix = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, characteristicKey);
    if (kvStore->DeleteByPrefix(profileKeyPrefix) != DP_SUCCESS) {
        HILOGE("DeleteCharacteristicProfile fail!");
        return DP_DEL_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().DeleteCharProfile(deviceId, serviceName, characteristicKey);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetAllDeviceProfile(std::shared_ptr<IKVAdapter> kvStore,
    std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("call!");
    std::map<std::string, std::string> values;
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (kvStore->GetByPrefix(DEV_PREFIX, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    std::map<std::string, std::map<std::string, std::string>> profileEntries;
    for (const auto& item : values) {
        std::string dbKey = item.first;
        std::string dbValue = item.second;
        std::string profileKey = ProfileUtils::GetProfileKey(dbKey);
        profileEntries[profileKey].emplace(dbKey, dbValue);
    }
    for (const auto& item : profileEntries) {
        DeviceProfile deviceProfile;
        ProfileUtils::EntriesToDeviceProfile(item.second, deviceProfile);
        deviceProfiles.push_back(deviceProfile);
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetAllServiceProfile(std::shared_ptr<IKVAdapter> kvStore,
    std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("call!");
    std::map<std::string, std::string> values;
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (kvStore->GetByPrefix(SVR_PREFIX, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    std::map<std::string, std::map<std::string, std::string>> profileEntries;
    for (const auto& item : values) {
        std::string dbKey = item.first;
        std::string dbValue = item.second;
        std::string profileKey = ProfileUtils::GetProfileKey(dbKey);
        profileEntries[profileKey].emplace(dbKey, dbValue);
    }
    for (const auto &item : profileEntries) {
        ServiceProfile serviceProfile;
        ProfileUtils::EntriesToServiceProfile(item.second, serviceProfile);
        serviceProfiles.push_back(serviceProfile);
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetAllCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
    std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    std::map<std::string, std::string> values;
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (kvStore->GetByPrefix(CHAR_PREFIX, values) != DP_SUCCESS) {
        HILOGE("Get data fail!");
        return DP_GET_KV_DB_FAIL;
    }
    std::map<std::string, std::map<std::string, std::string>> profileEntries;
    for (auto item : values) {
        std::string dbKey = item.first;
        std::string dbValue = item.second;
        std::string profileKey = ProfileUtils::GetProfileKey(dbKey);
        profileEntries[profileKey].emplace(dbKey, dbValue);
    }
    for (const auto& item : profileEntries) {
        CharacteristicProfile charProfile;
        ProfileUtils::EntriesToCharProfile(item.second, charProfile);
        charProfiles.push_back(charProfile);
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS