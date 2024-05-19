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

#include "listener/kv_data_change_listener.h"

#include <cinttypes>

#include "datetime_ex.h"
#include "string_ex.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "dynamic_profile_manager.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "subscribe_profile_manager.h"
#include "subscribe_profile_manager.h"
#include "distributed_device_profile_log.h"

#include "types.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvDataChangeListener";
}

KvDataChangeListener::KvDataChangeListener()
{
    HILOGI("construct!");
}

KvDataChangeListener::~KvDataChangeListener()
{
    HILOGI("destruct!");
}

void KvDataChangeListener::OnChange(const DistributedKv::ChangeNotification& changeNotification)
{
    HILOGI("KvDataChangeListener: DB data OnChange");
    ProfileCache::GetInstance().RefreshProfileCache();
    if (!changeNotification.GetInsertEntries().empty() &&
        changeNotification.GetInsertEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleAddChange(changeNotification.GetInsertEntries());
    }
    if (!changeNotification.GetUpdateEntries().empty() &&
        changeNotification.GetUpdateEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleUpdateChange(changeNotification.GetUpdateEntries());
    }
    if (!changeNotification.GetDeleteEntries().empty() &&
        changeNotification.GetDeleteEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleDeleteChange(changeNotification.GetDeleteEntries());
    }
}

void KvDataChangeListener::OnChange(const DistributedKv::DataOrigin& origin, Keys&& keys)
{
    HILOGI("Cloud data change. store=%{public}s", origin.store.c_str());
    ProfileCache::GetInstance().RefreshProfileCache();
    std::vector<DistributedKv::Entry> insertRecords = DynamicProfileManager::GetInstance()
        .GetEntriesByKeys(keys[ChangeOp::OP_INSERT]);
    if (!insertRecords.empty() && insertRecords.size() <= MAX_DB_RECORD_SIZE) {
        HandleAddChange(insertRecords);
    }
    std::vector<DistributedKv::Entry> updateRecords = DynamicProfileManager::GetInstance()
        .GetEntriesByKeys(keys[ChangeOp::OP_UPDATE]);
    if (!updateRecords.empty() && updateRecords.size() <= MAX_DB_RECORD_SIZE) {
        HandleUpdateChange(updateRecords);
    }
    std::vector<std::string> delKeys = keys[ChangeOp::OP_DELETE];
    if (!delKeys.empty() && delKeys.size() <= MAX_DB_RECORD_SIZE) {
        std::vector<DistributedKv::Entry> deleteRecords;
        for (const auto& key : delKeys) {
            DistributedKv::Entry entry;
            DistributedKv::Key kvKey(key);
            entry.key = kvKey;
            deleteRecords.emplace_back(entry);
        }
        HandleDeleteChange(deleteRecords);
    }
}

void KvDataChangeListener::OnSwitchChange(const DistributedKv::SwitchNotification &notification)
{
    HILOGI("KvDataChangeListener: DB data OnSwitchChange");
    if (notification.deviceId.empty()) {
        HILOGE("params are valid");
        return;
    }
    // is local or is online
    std::string netWorkId = notification.deviceId;
    std::string udid;
    int32_t res = ProfileCache::GetInstance().GetUdidByNetWorkId(netWorkId, udid);
    if (res != DP_SUCCESS || udid.empty()) {
        HILOGE("KvDataChangeListener: get udid fail, netWorkId is invalid: %s",
             ProfileUtils::GetAnonyString(netWorkId).c_str());
        return;
    }
    HandleSwitchUpdateChange(udid, notification.data.value);
}

void KvDataChangeListener::HandleAddChange(const std::vector<DistributedKv::Entry>& insertRecords)
{
    HILOGI("Handle kv data add change!");
    for (const auto& item : insertRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::ADD, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleUpdateChange(const std::vector<DistributedKv::Entry>& updateRecords)
{
    HILOGI("Handle kv data update change!");
    for (const auto& item : updateRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::UPDATE, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleDeleteChange(const std::vector<DistributedKv::Entry>& deleteRecords)
{
    HILOGI("Handle kv data delete change!");
    for (const auto& item : deleteRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::DELETE, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleSwitchUpdateChange(const std::string udid, uint32_t switchValue)
{
    HILOGI("Handle kv switch data update change!, udid: %{public}s, switch: %{public}u",
        ProfileUtils::GetAnonyString(udid).c_str(), switchValue);
    std::string serviceName;

    // std::lock_guard<std::mutex> lock(dataChangeListenerMutex_);
    for (int32_t i = (int32_t)SwitchFlag::SWITCH_FLAG_MIN + (int32_t)NUM_1U; i < (int32_t)SwitchFlag::SWITCH_FLAG_MAX; ++i) {
        std::string itemSwitchValue =  std::to_string((switchValue >> i) & NUM_1);
        int32_t res = ProfileCache::GetInstance().GetServiceNameByPos(i, SWITCH_SERVICE_MAP, serviceName);
        if (res != DP_SUCCESS || serviceName.empty()) {
            HILOGE("GetServiceNameByPos failed, serviceName:%s", serviceName.c_str());
            return;
        }
        res = GenerateSwitchNotify(udid, serviceName, SWITCH_STATUS,
                itemSwitchValue, ChangeType::UPDATE);
        if (res != DP_SUCCESS) {
            HILOGE("GenerateSwitchNotify failed, res: %d", res);
            return;
        }
        if (udid == ProfileCache::GetInstance().GetLocalUdid()) {
            ProfileCache::GetInstance().SetCurSwitch(switchValue);
            HILOGI("update curLocalSwitch: %{public}d", ProfileCache::GetInstance().GetSwitch());
        }
    }

}

int32_t KvDataChangeListener::GenerateSwitchNotify(const std::string& udid, const std::string& serviceName,
    const std::string& characteristicProfileKey, const std::string& characteristicProfileValue, ChangeType changeType)
{
    if (!ProfileUtils::IsKeyValid(udid) ||
        !ProfileUtils::IsKeyValid(serviceName) ||
        !ProfileUtils::IsKeyValid(characteristicProfileKey) ||
        !ProfileUtils::IsKeyValid(characteristicProfileValue)) {
        HILOGE("Params are invalid!");
        return DP_INVALID_PARAMS;
    }
    
    CharacteristicProfile newSwitchProfile = {udid, serviceName, characteristicProfileKey,
        characteristicProfileValue};
    HILOGI("Gen SwitchProfile :%{public}s", newSwitchProfile.dump().c_str());
    if (ProfileCache::GetInstance().IsCharProfileExist(newSwitchProfile)) {
        HILOGW("switch is not change");
        return DP_SUCCESS;
    }
    const CharacteristicProfile cacheProfile = newSwitchProfile;
    ProfileCache::GetInstance().AddCharProfile(cacheProfile);
    std::string dbKey = ProfileUtils::GetDbKeyByProfile(newSwitchProfile);
    ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
    int32_t res = SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, changeType, dbKey,
        newSwitchProfile.GetCharacteristicValue());
    if (res != DP_SUCCESS) {
        HILOGE("NotifyProfileChange failed");
        return DP_GENERATE_SWITCH_NOTIFY_FAIL;
    }
    HILOGI("NotifyProfileChange, deviceId:%{public}s, serviceName:%{public}s, GetCharacteristicValue:%{public}s",
        ProfileUtils::GetAnonyString(udid).c_str(), serviceName.c_str(),
        newSwitchProfile.GetCharacteristicValue().c_str());
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS