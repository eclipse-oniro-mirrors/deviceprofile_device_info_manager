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

#include <map>

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_log.h"
#include "multi_user_manager.h"
#include "profile_cache.h"
#include "profile_utils.h"
#include "switch_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ProfileControlUtils";
}
int32_t ProfileControlUtils::PutDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const DeviceProfile& deviceProfile)
{
    HILOGI("DeviceProfile : %{public}s!", deviceProfile.AnnoymizeDump().c_str());
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsDevProfileValid(deviceProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
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
    HILOGI("ServiceProfile : %{public}s!", serviceProfile.dump().c_str());
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsSvrProfileValid(serviceProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
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
    HILOGD("PutServiceProfileBatch call!");
    if (serviceProfiles.size() > MAX_SERVICE_SIZE) {
        HILOGE("serviceProfiles size is too large!");
        return DP_INVALID_PARAMS;
    }
    for (const auto& serviceProfile : serviceProfiles) {
        int32_t putServiceResult = PutServiceProfile(kvStore, serviceProfile);
        if (putServiceResult != DP_SUCCESS) {
            HILOGE("PutServiceProfile fail, serviceProfile: %{public}s, errcode: %{public}d!",
                serviceProfile.dump().c_str(), putServiceResult);
            continue;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
    const CharacteristicProfile& charProfile)
{
    HILOGI("Profile : %{public}s!", charProfile.dump().c_str());
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsCharProfileValid(charProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
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
    HILOGI("Profile : %{public}s!", charProfile.dump().c_str());
    if (!ProfileUtils::IsCharProfileValid(charProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    if (ProfileCache::GetInstance().IsCharProfileExist(charProfile)) {
        HILOGW("the profile is exist!");
        return DP_CACHE_EXIST;
    }
    uint32_t curSwitch = ProfileCache::GetInstance().GetSwitch();
    HILOGD("PutSwitchCharacteristicProfile curSwitch:%{public}d", curSwitch);
    uint32_t newSwitch = curSwitch;
    int32_t res = ProfileCache::GetInstance().SetSwitchByProfile(charProfile, SWITCH_SERVICE_MAP, newSwitch);
    if (res != DP_SUCCESS) {
        HILOGE("set switch profile failed: %{public}d", res);
        return res;
    }
    HILOGD("PutSwitchCharacteristicProfile newSwitch:%{public}d", newSwitch);
    res = SwitchAdapter::GetInstance().PutSwitch(appId, newSwitch, CUR_SWITCH_LEN);
    if (res != DP_SUCCESS) {
        HILOGE("put switch failed: %{public}d", res);
        return res;
    }
    ProfileCache::GetInstance().SetCurSwitch(newSwitch);
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::PutSwitchCharacteristicProfileBatch(const std::string& appId,
    const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("charProfiles.size:%{public}zu", charProfiles.size());
    if (charProfiles.empty() || appId.empty()) {
        HILOGE("charProfiles or appId are empty");
        return DP_INVALID_PARAMS;
    }
    if (charProfiles.size() > MAX_CHAR_SIZE) {
        HILOGE("charProfiles size is too large!");
        return DP_INVALID_PARAMS;
    }
    int32_t res = 0;
    uint32_t curSwitch = ProfileCache::GetInstance().GetSwitch();
    HILOGD("curSwitch:%{public}d", curSwitch);
    uint32_t newSwitch = curSwitch;
    for (auto item : charProfiles) {
        if (!ProfileUtils::IsCharProfileValid(item)) {
            HILOGE("a profile is invalid! charProfile: %{public}s", item.dump().c_str());
            return DP_INVALID_PARAMS;
        }
        if (ProfileCache::GetInstance().IsCharProfileExist(item)) {
            HILOGW("this profile is exist! charProfile: %{public}s", item.dump().c_str());
            continue;
        }
        HILOGI("charProfile: %{public}s!", item.dump().c_str());
        res = ProfileCache::GetInstance().SetSwitchByProfile(item, SWITCH_SERVICE_MAP, newSwitch);
        if (res != DP_SUCCESS) {
            HILOGW("set switch profile failed: %{public}d", res);
        }
    }
    HILOGD("newSwitch:%{public}d", newSwitch);
    res = SwitchAdapter::GetInstance().PutSwitch(appId, newSwitch, CUR_SWITCH_LEN);
    if (res != DP_SUCCESS) {
        HILOGE("put switch Batch failed: %{public}d", res);
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
    HILOGD("call!");
    if (charProfiles.size() > MAX_CHAR_SIZE) {
        HILOGE("charProfiles size is too large!");
        return DP_INVALID_PARAMS;
    }
    for (const auto& charProfile : charProfiles) {
        int32_t putCharacteristicResult = PutCharacteristicProfile(kvStore, charProfile);
        if (putCharacteristicResult != DP_SUCCESS) {
            HILOGE("PutCharacteristic fail, charProfile: %{public}s, errcode: %{public}d!", charProfile.dump().c_str(),
                putCharacteristicResult);
            continue;
        }
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    DeviceProfile& deviceProfile)
{
    HILOGD("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("GetDeviceProfile, deviceId: %{public}s!", ProfileUtils::GetAnonyString(deviceId).c_str());
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
    ProfileUtils::EntriesToDeviceProfile(values, deviceProfile);
    if (!ProfileUtils::IsDeviceProfileValid(deviceProfile)) {
        HILOGE("deviceProfile is invalid!");
        return DP_GET_KV_DB_FAIL;
    }
    HILOGD("GetDeviceProfile in db : %{public}s!", deviceProfile.AnnoymizeDump().c_str());
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    HILOGD("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceId: %{public}s, serviceName: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str());
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
    ProfileUtils::EntriesToServiceProfile(values, serviceProfile);
    if (!ProfileUtils::IsServiceProfileValid(serviceProfile)) {
        HILOGE("serviceProfile is invalid!");
        return DP_GET_KV_DB_FAIL;
    }
    HILOGD("GetServiceProfile in db : %{public}s!", serviceProfile.dump().c_str());
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("deviceId: %{public}s, serviceName: %{public}s, charKey: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr! devId: %{public}s, svrName: %{public}s, charKey: %{public}s!",
            ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey)) {
        HILOGE("the profile is invalid! devId: %{public}s, svrName: %{public}s, charKey: %{public}s!",
            ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
        return DP_INVALID_PARAMS;
    }
    if (characteristicKey == STATIC_CHARACTERISTIC_KEY || characteristicKey == SWITCH_STATUS) {
        if (ProfileCache::GetInstance().GetCharacteristicProfile(deviceId, serviceName, characteristicKey, charProfile)
            == DP_SUCCESS) {
            HILOGI("GetCharProfile in cache! devId: %{public}s, svrName: %{public}s, charKey: %{public}s!",
                ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
            return DP_SUCCESS;
        }
    }
    std::map<std::string, std::string> values;
    if (ProfileUtils::IsNeedAddOhSuffix(serviceName, true)) {
        std::string profileKeyPrefix = ProfileUtils::GenerateCharProfileKey(deviceId,
            ProfileUtils::CheckAndAddOhSuffix(serviceName, true), characteristicKey);
        if (kvStore->GetByPrefix(profileKeyPrefix, values) != DP_SUCCESS) {
            HILOGE("Get data by oh suffix fail! devId: %{public}s, svrName: %{public}s, charKey: %{public}s!",
                ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
            values.clear();
        }
    }
    if (values.empty()) {
        std::string profileKeyPrefix = ProfileUtils::GenerateCharProfileKey(deviceId, serviceName, characteristicKey);
        if (kvStore->GetByPrefix(profileKeyPrefix, values) != DP_SUCCESS) {
            HILOGE("Get data fail! devId: %{public}s, svrName: %{public}s, charKey: %{public}s!",
                ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
            return DP_GET_KV_DB_FAIL;
        }
    }
    ProfileUtils::EntriesToCharProfile(values, charProfile);
    if (!ProfileUtils::IsCharacteristicProfileValid(charProfile)) {
        HILOGE("charProfile is invalid!");
        return DP_GET_KV_DB_FAIL;
    }
    HILOGD("GetCharacteristicProfile in db : %{public}s!", charProfile.dump().c_str());
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::RefreshLocalSwitchProfile(const std::string& appId)
{
    HILOGD("call!");
    std::string localNetwork = ProfileCache::GetInstance().GetLocalNetworkId();
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    if (localNetwork.empty() || localUdid.empty() || appId.empty()) {
        HILOGE("params are empty");
        return DP_INVALID_PARAMS;
    }
    uint32_t newSwitch = 0;
    uint32_t switchLength = 0;
    int32_t res = SwitchAdapter::GetInstance().GetSwitch(appId, localNetwork, newSwitch, switchLength);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitch failed, res: %{public}d", res);
        return DP_GET_KV_DB_FAIL;
    }
    HILOGI("GetSwitch, newSwitch: %{public}d", newSwitch);
    for (int32_t i = static_cast<int32_t>(SwitchFlag::SWITCH_FLAG_MIN) + NUM_1;
        i < static_cast<int32_t>(SwitchFlag::SWITCH_FLAG_MAX); ++i) {
        HILOGD("Find Switch, idx: %{public}d", i);
        std::string itemSwitchValue = std::to_string((newSwitch >> i) & NUM_1);
        std::string serviceName;
        res = ProfileCache::GetInstance().GetServiceNameByPos(i, SWITCH_SERVICE_MAP, serviceName);
        if (res != DP_SUCCESS || serviceName.empty()) {
            HILOGE("GetServiceNameByPos failed, serviceName:%{public}s", serviceName.c_str());
            continue;
        }
        const CharacteristicProfile newSwitchProfile = {localUdid, serviceName, SWITCH_STATUS, itemSwitchValue};
        ProfileCache::GetInstance().AddCharProfile(newSwitchProfile);
    }
    ProfileCache::GetInstance().SetCurSwitch(newSwitch);
    HILOGI("update curLocalSwitch: %{public}d", ProfileCache::GetInstance().GetSwitch());
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetSwitchCharacteristicProfile(const std::string& appId, const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicKey) || appId.empty()) {
        HILOGE("params are invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceId: %{public}s, serviceName: %{public}s, charKey: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    if (ProfileCache::GetInstance().GetCharacteristicProfile(deviceId, serviceName, characteristicKey, charProfile)
        == DP_SUCCESS) {
        HILOGI("GetCharProfile in cache: %{public}s!", charProfile.dump().c_str());
        return DP_SUCCESS;
    }
    const CharacteristicProfile profile(deviceId, serviceName, characteristicKey, "");
    if (!ProfileCache::GetInstance().IsSwitchValid(profile, SWITCH_SERVICE_MAP, SWITCH_OPERATE_GET)) {
        HILOGE("params invalid");
        return DP_INVALID_PARAMS;
    }
    std::string netWorkId;
    int32_t res = ProfileCache::GetInstance().GetNetWorkIdByUdid(deviceId, netWorkId);
    if (res != DP_SUCCESS) {
        HILOGE("GetNetWorkIdByUdid failed, res: %{public}d", res);
        return DP_GET_KV_DB_FAIL;
    }
    uint32_t switchValue;
    uint32_t switchLength;
    res = SwitchAdapter::GetInstance().GetSwitch(appId, netWorkId, switchValue, switchLength);
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitch failed, res: %{public}d", res);
        return DP_GET_KV_DB_FAIL;
    }
    HILOGD("GetSwitch success, switchValue: %{public}d", switchValue);
    charProfile.SetDeviceId(deviceId);
    charProfile.SetServiceName(serviceName);
    charProfile.SetCharacteristicKey(characteristicKey);
    res = ProfileCache::GetInstance().SetSwitchProfile(charProfile, switchValue);
    if (res != DP_SUCCESS) {
        HILOGE("SetSwitchProfile failed, res: %{public}d", res);
        return DP_GET_KV_DB_FAIL;
    }
    HILOGI("success : %{public}s!", charProfile.dump().c_str());
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::DeleteServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    HILOGD("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsLocalUdid(deviceId) ||
        !ProfileUtils::IsKeyValid(serviceName)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceId: %{public}s, serviceName: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str());
    std::vector<std::string> keys;
    if (isMultiUser) {
        ProfileUtils::GenerateServiceDBkeys(deviceId, serviceName, keys, true, userId);
        if (MultiUserManager::GetInstance().GetCurrentForegroundUserID() == userId) {
            ProfileUtils::GenerateServiceDBkeys(deviceId, serviceName, keys);
        } else {
            HILOGI("the profile does not belong to the current user.");
        }
    } else {
        ProfileUtils::GenerateServiceDBkeys(deviceId, serviceName, keys);
    }
    if (kvStore->DeleteBatch(keys) != DP_SUCCESS) {
        HILOGE("DeleteServiceProfile fail!");
        return DP_DEL_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::DeleteServiceInfoProfile(std::shared_ptr<IKVAdapter> kvStore, int32_t regServiceId,
    int32_t userId)
{
    HILOGD("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    std::string strRegServiceId = std::to_string(regServiceId);
    std::vector<std::string> keys;
    ProfileUtils::GenerateServiceInfoProfilekeys(strRegServiceId, keys, userId);
    if (keys.empty()) {
        return DP_SUCCESS;
    }
    if (kvStore->DeleteBatch(keys) != DP_SUCCESS) {
        HILOGE("DeleteServiceProfile fail!");
        return DP_DEL_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::DeleteCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
    const std::string& deviceId, const std::string& serviceName, const std::string& characteristicKey, bool isMultiUser,
    int32_t userId)
{
    HILOGI("call!");
    if (kvStore == nullptr) {
        HILOGE("kvStore is nullptr!");
        return DP_INVALID_PARAMS;
    }
    if (!ProfileUtils::IsKeyValid(deviceId) || !ProfileUtils::IsLocalUdid(deviceId) ||
        !ProfileUtils::IsKeyValid(serviceName) || !ProfileUtils::IsKeyValid(characteristicKey)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    HILOGI("deviceId: %{public}s, serviceName: %{public}s, charKey: %{public}s!",
        ProfileUtils::GetAnonyString(deviceId).c_str(), serviceName.c_str(), characteristicKey.c_str());
    std::vector<std::string> keys;
    if (isMultiUser) {
        ProfileUtils::GenerateCharacteristicDBkeys(deviceId, serviceName, characteristicKey, keys, true, userId);
        if (MultiUserManager::GetInstance().GetCurrentForegroundUserID() == userId) {
            ProfileUtils::GenerateCharacteristicDBkeys(deviceId, serviceName, characteristicKey, keys);
        } else {
            HILOGI("the profile does not belong to the current user.");
        }
    } else {
        ProfileUtils::GenerateCharacteristicDBkeys(deviceId, serviceName, characteristicKey, keys);
    }
    if (kvStore->DeleteBatch(keys) != DP_SUCCESS) {
        HILOGE("DeleteCharacteristicProfile fail!");
        return DP_DEL_KV_DB_FAIL;
    }
    ProfileCache::GetInstance().DeleteCharProfile(deviceId, serviceName, characteristicKey);
    return DP_SUCCESS;
}

int32_t ProfileControlUtils::GetAllDeviceProfile(std::shared_ptr<IKVAdapter> kvStore,
    std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGD("call!");
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
    HILOGD("call!");
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
    HILOGD("call!");
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
