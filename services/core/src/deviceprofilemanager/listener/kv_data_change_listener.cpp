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

#include <algorithm>
#include <cinttypes>
#include <thread>

#include "datetime_ex.h"
#include "string_ex.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "device_profile_manager.h"
#include "profile_utils.h"
#include "profile_cache.h"
//delete start
#include "subscribe_profile_manager.h"
//delete end
#include "subscribe_profile_manager.h"
#include "distributed_device_profile_log.h"
#include "service_info.h"
#include "i_service_info_change_callback.h"
#include "service_info_change_proxy.h"
#include "types.h"
#include "service_info_manager.h"
#include "subscribe_service_info_manager.h"
#include "parameter.h"
#include "ffrt.h"
#include "cJSON.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvDataChangeListener";
    const std::string STATIC_STORE_ID = "dp_kv_static_store";
    constexpr uint32_t MAX_SWITCH_CACHE_SIZE = 1000;
    constexpr int32_t DEVICE_UUID_LENGTH = 65;
}

KvDataChangeListener::KvDataChangeListener(const std::string& storeId)
{
    HILOGD("construct!");
    storeId_ = storeId;
}

KvDataChangeListener::~KvDataChangeListener()
{
    HILOGD("destruct!");
}

void KvDataChangeListener::OnChange(const DistributedKv::ChangeNotification& changeNotification)
{
    HILOGI("storeId=%{public}s", storeId_.c_str());
    if (storeId_ == STATIC_STORE_ID) {
        return;
    }
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
    if (origin.store == STATIC_STORE_ID) {
        HILOGI("Sync data Change. store=%{public}s", origin.store.c_str());
        auto task = [this, origin, keys]() {
            ProcessChangeOp(keys[ChangeOp::OP_INSERT], ChangeOp::OP_INSERT);
            ProcessChangeOp(keys[ChangeOp::OP_UPDATE], ChangeOp::OP_UPDATE);
            ProcessChangeOp(keys[ChangeOp::OP_DELETE], ChangeOp::OP_DELETE);
        };

        std::thread(task).detach();
        return;
    }

    HILOGI("Cloud data Change. store=%{public}s", origin.store.c_str());
    std::vector<DistributedKv::Entry> insertRecords = DeviceProfileManager::GetInstance()
        .GetEntriesByKeys(keys[ChangeOp::OP_INSERT]);
    if (!insertRecords.empty() && insertRecords.size() <= MAX_DB_RECORD_SIZE) {
        HandleAddChange(insertRecords);
    }
    std::vector<DistributedKv::Entry> updateRecords = DeviceProfileManager::GetInstance()
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

void KvDataChangeListener::ProcessChangeOp(const std::vector<std::string>& keyList, ChangeOp op)
{
    std::vector<ServiceInfo> serviceInfos;
    std::string localUdid;
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    localUdid = localUdidTemp;

    switch (op) {
        case OP_INSERT:
            ProcessInsertOrUpdate(keyList, localUdid, serviceInfos);
            if (!serviceInfos.empty()) {
                SubscribeServiceInfoManager::GetInstance().NotifyServiceInfoAdd(serviceInfos);
            }
            break;
        case OP_UPDATE:
            ProcessInsertOrUpdate(keyList, localUdid, serviceInfos);
            if (!serviceInfos.empty()) {
                SubscribeServiceInfoManager::GetInstance().NotifyServiceInfoUpdate(serviceInfos);
            }
            break;
            
        case OP_DELETE:
            ProcessDelete(keyList, localUdid, serviceInfos);
            if (!serviceInfos.empty()) {
                SubscribeServiceInfoManager::GetInstance().NotifyServiceInfoDelete(serviceInfos);
            }
            break;
            
        case OP_BUTT:
            HILOGE("Invalid operation type: OP_BUTT");
            return;
            
        default:
            HILOGW("Unsupported operation type: %{public}d", static_cast<int>(op));
            return;
    }
}

void KvDataChangeListener::ConvertRecordsToMap(const std::vector<DistributedKv::Entry>& records,
    std::map<std::string, std::string>& entriesMap)
{
    for (const auto& item : records) {
        std::string dbKey = item.key.ToString();

        std::vector<std::string> res;
        if (ProfileUtils::SplitString(dbKey, SEPARATOR, res) == DP_SUCCESS &&
            res.size() == MIN_KEY_PARTS_REQUIRED) {
            if (res[SERINFO_INDEX] != SERINFO_PREFIX) {
                HILOGE("%{public}s is invalid", dbKey.c_str());
                continue;
            }
        }
        entriesMap[dbKey] = item.value.ToString();
    }
}

void KvDataChangeListener::ProcessInsertOrUpdate(const std::vector<std::string>& keyList,
    const std::string& localUdid, std::vector<ServiceInfo>& serviceInfos)
{
    std::vector<DistributedKv::Entry> allentries =
        ServiceInfoManager::GetInstance().GetEntriesByKeys(keyList);

    if (allentries.empty() || allentries.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Invalid entries size: %{public}zu", allentries.size());
        return;
    }

    std::map<std::string, std::string> entries;
    ConvertRecordsToMap(allentries, entries);

    for (const auto& [dbKey, dbValue] : entries) {
        cJSON* jsonObj = cJSON_Parse(dbValue.c_str());
        if (jsonObj == nullptr) {
            HILOGE("Parse JSON failed for key: %{public}s", dbKey.c_str());
            continue;
        }

        ParsedJSONFields fields;
        if (!ServiceInfoManager::GetInstance().ParseAndValidateJSON(jsonObj, fields)) {
            cJSON_Delete(jsonObj);
            HILOGE("ParseAndValidateJSON failed for key: %{public}s", dbKey.c_str());
            continue;
        }

        ServiceInfo serviceInfo;
        ServiceInfoManager::GetInstance().FillServiceInfo(fields, serviceInfo);

        if (ServiceInfoManager::GetInstance().PutServiceInfo(serviceInfo) == DP_SUCCESS &&
            serviceInfo.GetUdid() != localUdid) {
            serviceInfos.push_back(serviceInfo);
        }
        cJSON_Delete(jsonObj);
    }
}

void KvDataChangeListener::ProcessDelete(const std::vector<std::string>& keyList,
    const std::string& localUdid, std::vector<ServiceInfo>& serviceInfos)
{
    if (keyList.empty() || keyList.size() > MAX_DB_RECORD_SIZE) {
        HILOGE("Invalid key list size: %{public}zu", keyList.size());
        return;
    }

    std::vector<DistributedKv::Entry> deleteRecords;
    for (const auto &key : keyList) {
        DistributedKv::Entry entry;
        DistributedKv::Key kvKey(key);
        entry.key = kvKey;
        deleteRecords.emplace_back(entry);
    }

    std::map<std::string, std::string> entries;
    ConvertRecordsToMap(deleteRecords, entries);

    for (const auto& [dbKey, dbValue] : entries) {
        UserInfo userInfo;
        ServiceInfo serviceInfo;
        if (EntriesToUserInfo(dbKey, userInfo, serviceInfo) != DP_SUCCESS) {
            HILOGE("Failed to parse user info from key");
            continue;
        }
        if (ServiceInfoManager::GetInstance().DeleteServiceInfo(userInfo) == DP_SUCCESS &&
            userInfo.udid != localUdid) {
            serviceInfos.push_back(serviceInfo);
        }
    }
}

int32_t KvDataChangeListener::EntriesToUserInfo(const std::string& key, UserInfo& userInfo, ServiceInfo& serviceInfo)
{
    std::vector<std::string> res;
    std::vector<ServiceInfo> serviceInfos;
    if (ProfileUtils::SplitString(key, SEPARATOR, res) != DP_SUCCESS ||
        res.size() != MIN_KEY_PARTS_REQUIRED) {
        HILOGE("key is invalid: %{public}s", key.c_str());
        return DP_INVALID_PARAMS;
    }

    userInfo.udid = res[UDID_INDEX];
    userInfo.userId = std::atoi(res[USERID_INDEX].c_str());
    userInfo.serviceId = std::atoll(res[SERVICEID_INDEX].c_str());

    int ret = ServiceInfoManager::GetInstance().GetServiceInfosByUserInfo(userInfo, serviceInfos);
    if (ret != DP_SUCCESS) {
        HILOGE("GetServiceInfosByUserInfo Fail");
        return ret;
    }
    if (!serviceInfos.empty()) {
        serviceInfo = serviceInfos[NUM_0];
    }

    return DP_SUCCESS;
}

void KvDataChangeListener::OnSwitchChange(const DistributedKv::SwitchNotification& notification)
{
    auto task = [notification]() {
        HILOGI("OnSwitchChange Switch data change, networkid: %{public}s",
            ProfileUtils::GetAnonyString(notification.deviceId).c_str());
        if (notification.deviceId.empty()) {
            HILOGE("OnSwitchChange params are valid");
            return;
        }
        // is local or is online
        std::string netWorkId = notification.deviceId;
        std::string udid;
        int32_t res = ProfileCache::GetInstance().GetUdidByNetWorkId(netWorkId, udid);
        if (res == DP_GET_UDID_BY_NETWORKID_FAIL) {
            SwitchUpdater::GetInstance().AddSwitchCacheMap(netWorkId, notification.data.value);
            HILOGI("OnSwitchChange device is not online,already add cache,netWorkId:%{public}s,switch:%{public}u",
                ProfileUtils::GetAnonyString(netWorkId).c_str(), notification.data.value);
            return;
        }
        if (res != DP_SUCCESS || udid.empty()) {
            HILOGD("OnSwitchChange get udid fail, netWorkId is invalid: %{public}s",
                ProfileUtils::GetAnonyString(netWorkId).c_str());
            return;
        }
        SwitchUpdater::GetInstance().EraseSwitchCacheMap(netWorkId);
        SwitchUpdater::GetInstance().HandleSwitchUpdateChange(udid, notification.data.value);
    };
    std::thread(task).detach();
}

void KvDataChangeListener::FilterEntries(const std::vector<DistributedKv::Entry>& records,
    std::map<std::string, std::string>& entriesMap, bool isDelete)
{
    std::map<std::string, std::string> ohSuffix2NonMaps;
    std::map<std::string, std::string> non2OhSuffixMaps;
    for (const auto& item : records) {
        std::string dbKey = item.key.ToString();
        std::vector<std::string> res;
        if (ProfileUtils::SplitString(dbKey, SEPARATOR, res) != DP_SUCCESS || res.size() < NUM_3) {
            HILOGW("invalid dbkey(%{public}s)", ProfileUtils::GetDbKeyAnonyString(dbKey).c_str());
            continue;
        }
        if (res[0] != DEV_PREFIX && res[0] != SVR_PREFIX && res[0] != CHAR_PREFIX) {
            HILOGW("%{public}s is invalid dbKey", ProfileUtils::GetDbKeyAnonyString(dbKey).c_str());
            continue;
        }
        if (res[0] == CHAR_PREFIX && res.size() > NUM_4 && res[NUM_4] == CHARACTERISTIC_KEY) {
            HILOGD("%{public}s is charProfileKey", ProfileUtils::GetDbKeyAnonyString(dbKey).c_str());
            continue;
        }
        entriesMap[dbKey] = item.value.ToString();
        if (ProfileUtils::EndsWith(res[NUM_2], OH_PROFILE_SUFFIX)) {
            res[NUM_2] = ProfileUtils::CheckAndRemoveOhSuffix(res[NUM_2]);
            ohSuffix2NonMaps[dbKey] = ProfileUtils::JoinString(res, SEPARATOR);
            continue;
        }
        if (ProfileUtils::IsNeedAddOhSuffix(res[NUM_2], res.front() == SVR_PREFIX)) {
            res[NUM_2] = ProfileUtils::CheckAndAddOhSuffix(res[NUM_2], res.front() == SVR_PREFIX);
            non2OhSuffixMaps[dbKey] = ProfileUtils::JoinString(res, SEPARATOR);
            continue;
        }
    }
    for (const auto& [ohSuffixKey, nonOhSuffixKey] : ohSuffix2NonMaps) {
        entriesMap.erase(nonOhSuffixKey);
        non2OhSuffixMaps.erase(nonOhSuffixKey);
    }
    ohSuffix2NonMaps.clear();
    if (isDelete) { return; }
    if (non2OhSuffixMaps.empty()) { return; }
    std::vector<std::string> ohSuffixKeys;
    for (const auto& [nonOhSuffixKey, ohSuffixKey] : non2OhSuffixMaps) {
        ohSuffix2NonMaps[ohSuffixKey] = nonOhSuffixKey;
        ohSuffixKeys.emplace_back(ohSuffixKey);
    }
    std::vector<DistributedKv::Entry> entries = DeviceProfileManager::GetInstance().GetEntriesByKeys(ohSuffixKeys);
    if (entries.empty()) { return; }
    for (const auto& item : entries) {
        entriesMap.erase(ohSuffix2NonMaps[item.key.ToString()]);
    }
}

void KvDataChangeListener::HandleAddChange(const std::vector<DistributedKv::Entry>& insertRecords)
{
    HILOGD("Handle kv data add change!");
    std::map<std::string, std::string> entries;
    FilterEntries(insertRecords, entries, false);
    for (const auto& [dbKey, dbValue] : entries) {
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::ADD, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleUpdateChange(const std::vector<DistributedKv::Entry>& updateRecords)
{
    HILOGD("Handle kv data update change!");
    std::map<std::string, std::string> entries;
    FilterEntries(updateRecords, entries, false);
    for (const auto& [dbKey, dbValue] : entries) {
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::UPDATE, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleDeleteChange(const std::vector<DistributedKv::Entry>& deleteRecords)
{
    HILOGD("Handle kv data delete change!");
    std::map<std::string, std::string> entries;
    FilterEntries(deleteRecords, entries, true);
    for (const auto& [dbKey, dbValue] : entries) {
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::DELETE, dbKey, dbValue);
    }
}

IMPLEMENT_SINGLE_INSTANCE(SwitchUpdater);

void SwitchUpdater::OnDeviceOnline(const TrustedDeviceInfo& deviceInfo)
{
    std::string onlineNetworkId = deviceInfo.GetNetworkId();
    if (onlineNetworkId.empty()) {
        HILOGE("onlineNetworkId is empty");
        return;
    }
    std::string onlineUdid = deviceInfo.GetUdid();
    if (onlineUdid.empty()) {
        HILOGE("onlineUdid is empty");
        return;
    }
    HILOGI("netWorkId:%{public}s", ProfileUtils::GetAnonyString(onlineNetworkId).c_str());
    std::lock_guard<std::mutex> lock(switchCacheMapMutex_);
    auto item = switchCacheMap_.find(onlineNetworkId);
    if (item == switchCacheMap_.end()) {
        HILOGI("onlineDevice not in cache");
        return;
    }
    uint32_t switchValue = item->second;
    HandleSwitchUpdateChange(onlineUdid, switchValue);
    switchCacheMap_.erase(item);
    HILOGI("end");
}

void SwitchUpdater::HandleSwitchUpdateChange(const std::string& udid, uint32_t switchValue)
{
    HILOGI("udid: %{public}s, switch: %{public}u", ProfileUtils::GetAnonyString(udid).c_str(), switchValue);
    std::string serviceName;

    for (int32_t i = (int32_t)SwitchFlag::SWITCH_FLAG_MIN + NUM_1;
        i < (int32_t)SwitchFlag::SWITCH_FLAG_MAX; ++i) {
        std::string itemSwitchValue = std::to_string((switchValue >> i) & NUM_1);
        int32_t res = ProfileCache::GetInstance().GetServiceNameByPos(i, SWITCH_SERVICE_MAP, serviceName);
        if (res != DP_SUCCESS || serviceName.empty()) {
            HILOGE("GetServiceNameByPos failed, pos:%{public}d", i);
            return;
        }
        res = GenerateSwitchNotify(udid, serviceName, SWITCH_STATUS,
        itemSwitchValue, ChangeType::UPDATE);
        if (res != DP_SUCCESS) {
            HILOGE("GenerateSwitchNotify failed, res: %{public}d", res);
            return;
        }
        if (udid == ProfileCache::GetInstance().GetLocalUdid()) {
            ProfileCache::GetInstance().SetCurSwitch(switchValue);
            HILOGD("update curLocalSwitch: %{public}d", ProfileCache::GetInstance().GetSwitch());
        }
    }
}

int32_t SwitchUpdater::GenerateSwitchNotify(const std::string& udid, const std::string& serviceName,
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
    return DP_SUCCESS;
}

void SwitchUpdater::AddSwitchCacheMap(const std::string& netWorkId, uint32_t switchValue)
{
    std::lock_guard<std::mutex> lock(switchCacheMapMutex_);
    if (switchCacheMap_.size() > MAX_SWITCH_CACHE_SIZE) {
        HILOGE("too many values!");
        return;
    }
    switchCacheMap_[netWorkId] = switchValue;
}

void SwitchUpdater::EraseSwitchCacheMap(const std::string& netWorkId)
{
    std::lock_guard<std::mutex> lock(switchCacheMapMutex_);
    switchCacheMap_.erase(netWorkId);
}
} // namespace DeviceProfile
} // namespace OHOS
