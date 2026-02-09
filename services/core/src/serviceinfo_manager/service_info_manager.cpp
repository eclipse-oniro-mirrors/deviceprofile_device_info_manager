/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "service_info_manager.h"
#include "profile_utils.h"

#include <unordered_set>

//delete start
#include "service_info_profile_new.h"
//delete end
#include "service_info.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "kv_data_change_listener.h"
#include "kv_store_death_recipient.h"
#include "kv_sync_completed_listener.h"
#include "profile_control_utils.h"

#include "multi_user_manager.h"
#include "parameter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoManager)
//delete start
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoProfileManage)
//delete end

namespace {
    const std::string STORE_ID = "dp_kv_store_service_info_profile";
    const std::string TAG = "ServiceInfoManager";
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string SYNC_STORE_ID = "dp_kv_static_store";
    constexpr int32_t DEVICE_UUID_LENGTH = 65;
}
int32_t ServiceInfoManager::Init()
{
    HILOGI("call!");
    std::lock_guard<std::mutex> lock(storeMutex_);
    serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t localRet = serviceInfoKvAdapter_->Init();
    if (localRet != DP_SUCCESS) {
        HILOGE("local KV adapters init failed, ret: %{public}d", localRet);
        return DP_INIT_DB_FAILED;
    }
    syncServiceInfoKvAdapter_ = std::make_shared<KVAdapter>(
        APP_ID, SYNC_STORE_ID, std::make_shared<KvDataChangeListener>(SYNC_STORE_ID),
        nullptr, std::make_shared<KvDeathRecipient>(SYNC_STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t syncRet = syncServiceInfoKvAdapter_->Init();
    if (syncRet != DP_SUCCESS) {
        HILOGE("sync KV adapters init failed, ret: %{public}d", syncRet);
        if (serviceInfoKvAdapter_ != nullptr) {
            serviceInfoKvAdapter_->UnInit();
        }
        syncServiceInfoKvAdapter_.reset();
        return DP_INIT_DB_FAILED;
    }
    HILOGI("Both local and sync KV adapters initialized successfully");
    return DP_SUCCESS;
}

int32_t ServiceInfoManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        serviceInfoKvAdapter_->UnInit();
        serviceInfoKvAdapter_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(syncStoreMutex_);
        if (syncServiceInfoKvAdapter_ == nullptr) {
            HILOGE("syncServiceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        syncServiceInfoKvAdapter_->UnInit();
        syncServiceInfoKvAdapter_ = nullptr;
    }
    HILOGI("UnInit success");
    return DP_SUCCESS;
}
int32_t ServiceInfoManager::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t ServiceInfoManager::PutServiceInfo(const ServiceInfo &serviceInfo)
{
    HILOGI("PutServiceInfo: %{public}s", serviceInfo.dump().c_str());

    if (!ProfileUtils::IsSvrInfoValid(serviceInfo)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::ServiceInfoToEntries(serviceInfo, entries);
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (serviceInfoKvAdapter_->PutBatch(entries) != DP_SUCCESS) {
            return DP_PUT_KV_DB_FAIL;
        }
    }
    std::string udid = serviceInfo.GetUdid();
    std::string localUdid = "";
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    localUdid = localUdidTemp;
    if (udid != localUdid) {
        HILOGI("Non-local data");
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(syncStoreMutex_);
        if (syncServiceInfoKvAdapter_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (syncServiceInfoKvAdapter_->PutBatch(entries) != DP_SUCCESS) {
            return DP_PUT_KV_DB_FAIL;
        }
    }

    HILOGI("PutServiceInfo success");
    return DP_SUCCESS;
}

int32_t ServiceInfoManager::DeleteServiceInfo(const UserInfo& userInfo)
{
    HILOGI("DeleteServiceInfo: %{public}s", userInfo.dump().c_str());
    if (userInfo.udid.empty()) {
        HILOGE("udid is required but empty");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    std::string prefix = "serInfo" + SEPARATOR + userInfo.udid + SEPARATOR;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }

        if (serviceInfoKvAdapter_->GetByPrefix(prefix, entries) != DP_SUCCESS) {
            HILOGE("Query entries failed for prefix: %{public}s",
                ProfileUtils::GetDbKeyAnonyString(prefix).c_str());
            return DP_GET_KV_DB_FAIL;
        }
    }
    std::vector<std::string> matchedKeys;
    for (const auto &entry : entries) {
        std::string remaining = entry.first.substr(prefix.length());
        if (IsKeyMatch(remaining, userInfo)) {
            matchedKeys.push_back(entry.first);
        }
    }
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_->DeleteBatch(matchedKeys) != DP_SUCCESS) {
            HILOGE("Batch delete failed for %{public}zu entries", matchedKeys.size());
            return DP_DEL_KV_DB_FAIL;
        }
    }
    char localUdidTemp[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localUdidTemp, DEVICE_UUID_LENGTH);
    std::string localUdid = localUdidTemp;
    if (userInfo.udid != localUdid) {
        HILOGI("Non-local data");
        return DP_SUCCESS;
    }

    int ret = DeleteSyncServiceInfo(matchedKeys);
    if (ret != DP_SUCCESS) {
        return ret;
    }
    HILOGI("DeleteServiceInfo success");
    return DP_SUCCESS;
}

int32_t ServiceInfoManager::GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("GetAllServiceInfoList");
    std::map<std::string, std::string> allEntries;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter is nullptr");
            return DP_KV_DB_PTR_NULL;
        }

        int32_t ret = serviceInfoKvAdapter_->GetByPrefix("", allEntries);
        if (ret != DP_SUCCESS) {
            HILOGE("GetByPrefix fail, ret: %{public}d", ret);
            return ret;
        }
    }
    for (const auto &entry : allEntries) {
        const std::string& keyStr = entry.first;
        const std::string& value = entry.second;

        cJSON *jsonObj = cJSON_Parse(value.c_str());
        if (jsonObj == nullptr) {
            HILOGE("Parse JSON failed for key: %{public}s", keyStr.c_str());
            continue;
        }

        ParsedJSONFields fields;
        if (!ParseAndValidateJSON(jsonObj, fields)) {
            cJSON_Delete(jsonObj);
            return DP_INVALID_PARAMS;
        }
        ServiceInfo serviceInfo;
        FillServiceInfo(fields, serviceInfo);
        serviceInfos.push_back(serviceInfo);
        cJSON_Delete(jsonObj);
    }
    HILOGI("Get all serviceInfo success, count: %{public}zu", serviceInfos.size());
    return DP_SUCCESS;
}

int32_t ServiceInfoManager::GetServiceInfosByUserInfo(const UserInfo& userInfo, std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("GetServiceInfosByPeerUserInfo");
    if (userInfo.udid.empty()) {
        HILOGE("udid is required but empty");
        return DP_INVALID_PARAMS;
    }

    std::map<std::string, std::string> allEntries;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t ret = serviceInfoKvAdapter_->GetByPrefix("", allEntries);
        if (ret != DP_SUCCESS) {
            HILOGE("GetByPrefix fail, ret: %{public}d", ret);
            return ret;
        }
    }

    for (const auto &entry : allEntries) {
        int32_t ret = ProcessServiceInfoEntry(entry.first, entry.second, userInfo, serviceInfos);
        if (ret != DP_SUCCESS) {
            HILOGE("ProcessServiceInfoEntry fail, ret: %{public}d", ret);
            return ret;
        }
    }

    if (serviceInfos.empty()) {
        HILOGE("No match ServiceInfo for UserInfo: udid=%{public}s, userId=%{public}d, serviceId=%{public}" PRId64,
            userInfo.udid.c_str(), userInfo.userId, userInfo.serviceId);
        return DP_NOT_FIND_DATA;
    }

    HILOGI("GetServiceInfosByPeerUserInfo success");
    return DP_SUCCESS;
}

std::vector<DistributedKv::Entry> ServiceInfoManager::GetEntriesByKeys(const std::vector<std::string>& keys)
{
    HILOGI("call!");
    std::vector<DistributedKv::Entry> entries;
    if (keys.empty()) {
        HILOGE("keys empty.");
        return entries;
    }
    {
        std::lock_guard<std::mutex> lock(syncStoreMutex_);
        if (syncServiceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter is nullptr!");
            return entries;
        }
        for (const auto& key : keys) {
            std::string value;
            if (syncServiceInfoKvAdapter_->Get(key, value) != DP_SUCCESS) {
                continue;
            }
            DistributedKv::Entry entry;
            DistributedKv::Key kvKey(key);
            entry.key = kvKey;
            entry.value = value;
            entries.emplace_back(entry);
            HILOGE("Found value for key: %{public}s, value: %{public}s",
                key.c_str(), value.c_str());
        }
    }
    return entries;
}

bool ServiceInfoManager::IsKeyMatch(const std::string& remaining, const UserInfo& userInfo)
{
    std::vector<std::string> parts;
    if (ProfileUtils::SplitString(remaining, SEPARATOR, parts) || parts.size() != KEY_PARTS_INDEX) {
        HILOGE("remaining is invalid");
        return false;
    }
    if (userInfo.userId == DEFAULT_ID && userInfo.serviceId == DEFAULT_SERVICE_ID) {
        return true;
    }
    if (userInfo.userId != DEFAULT_ID && userInfo.serviceId == DEFAULT_SERVICE_ID) {
        return parts[KEY_USERID_INDEX] == std::to_string(userInfo.userId);
    }
    if (userInfo.userId == DEFAULT_ID && userInfo.serviceId != DEFAULT_SERVICE_ID) {
        return parts[KEY_SERVICEID_INDEX] == std::to_string(userInfo.serviceId);
    }
    return parts[KEY_USERID_INDEX] == std::to_string(userInfo.userId) &&
        parts[KEY_SERVICEID_INDEX] == std::to_string(userInfo.serviceId);
}

bool ServiceInfoManager::ParseAndValidateJSON(cJSON* jsonObj, ParsedJSONFields& fields)
{
    fields.udidItem = cJSON_GetObjectItem(jsonObj, UD_ID.c_str());
    fields.userIdItem = cJSON_GetObjectItem(jsonObj, USER_ID.c_str());
    fields.serviceIdItem = cJSON_GetObjectItem(jsonObj, SERVICEID.c_str());
    fields.displayIdItem = cJSON_GetObjectItem(jsonObj, DISPLAYID.c_str());
    fields.serviceOwnerTokenIdItem = cJSON_GetObjectItem(jsonObj, SERVICE_OWNER_TOKEN_ID.c_str());
    fields.serviceOwnerPkgNameItem = cJSON_GetObjectItem(jsonObj, SERVICE_OWNER_PKG_NAME.c_str());
    fields.serviceRegisterTokenIdItem = cJSON_GetObjectItem(jsonObj, SERVICE_REGISTER_TOKEN_ID.c_str());
    fields.timeStampItem = cJSON_GetObjectItem(jsonObj, TIME_STAMP.c_str());
    fields.publishStateItem = cJSON_GetObjectItem(jsonObj, PUBLISH_STATE.c_str());
    fields.serviceTypeItem = cJSON_GetObjectItem(jsonObj, SERVICE_TYPE.c_str());
    fields.serviceNameItem = cJSON_GetObjectItem(jsonObj, SERVICE_NAME.c_str());
    fields.serviceDisplayNameItem = cJSON_GetObjectItem(jsonObj, SERVICE_DISPLAY_NAME.c_str());
    fields.customDataItem = cJSON_GetObjectItem(jsonObj, CUSTOM_DATA.c_str());
    fields.serviceCodeItem = cJSON_GetObjectItem(jsonObj, SERVICE_CODE.c_str());
    fields.dataLenItem = cJSON_GetObjectItem(jsonObj, DATA_LEN.c_str());
    fields.extraDataItem = cJSON_GetObjectItem(jsonObj, EXTRA_DATA.c_str());
    fields.versionItem = cJSON_GetObjectItem(jsonObj, VERSION.c_str());
    fields.descriptionItem = cJSON_GetObjectItem(jsonObj, DESCRIPTION.c_str());

    if (!ValidateStringFields(fields)) {
        HILOGE("ValidateStringFields fail");
        return false;
    }
    if (!ValidateNumberFields(fields)) {
        HILOGE("ValidateNumberFields fail");
        return false;
    }
    return true;
}

bool ServiceInfoManager::IsStringFieldValid(const cJSON* item)
{
    return item != nullptr && item->valuestring != nullptr;
}

bool ServiceInfoManager::ValidateStringFields(const ParsedJSONFields& fields)
{
    if (!IsStringFieldValid(fields.udidItem) ||
        !IsStringFieldValid(fields.serviceOwnerPkgNameItem) ||
        !IsStringFieldValid(fields.serviceTypeItem) ||
        !IsStringFieldValid(fields.serviceNameItem) ||
        !IsStringFieldValid(fields.serviceDisplayNameItem) ||
        !IsStringFieldValid(fields.customDataItem) ||
        !IsStringFieldValid(fields.serviceCodeItem) ||
        !IsStringFieldValid(fields.extraDataItem) ||
        !IsStringFieldValid(fields.versionItem) ||
        !IsStringFieldValid(fields.descriptionItem) ||
        !IsStringFieldValid(fields.displayIdItem) ||
        !IsStringFieldValid(fields.serviceIdItem) ||
        !IsStringFieldValid(fields.timeStampItem)) {
        HILOGE("Missing required string fields in JSON");
        return false;
    }

    return true;
}

bool ServiceInfoManager::ValidateNumberFields(const ParsedJSONFields& fields)
{
    if (!fields.userIdItem || !fields.serviceOwnerTokenIdItem ||
        !fields.serviceRegisterTokenIdItem || !fields.publishStateItem ||
        !fields.dataLenItem) {
        HILOGE("Missing required number fields in JSON");
        return false;
    }

    if (!cJSON_IsNumber(fields.userIdItem) ||
        !cJSON_IsNumber(fields.serviceOwnerTokenIdItem) ||
        !cJSON_IsNumber(fields.serviceRegisterTokenIdItem) ||
        !cJSON_IsNumber(fields.publishStateItem) ||
        !cJSON_IsNumber(fields.dataLenItem)) {
        HILOGE("Invalid number field in JSON");
        return false;
    }

    if (!ProfileUtils::IsNumStr(fields.displayIdItem->valuestring) ||
        !ProfileUtils::IsNumStr(fields.serviceIdItem->valuestring) ||
        !ProfileUtils::IsNumStr(fields.timeStampItem->valuestring)) {
        HILOGE("Non-numeric string in JSON");
        return false;
    }

    return true;
}

void ServiceInfoManager::FillServiceInfo(const ParsedJSONFields& fields, ServiceInfo& serviceInfo)
{
    serviceInfo.SetUdid(fields.udidItem->valuestring);
    serviceInfo.SetUserId(fields.userIdItem->valueint);
    serviceInfo.SetDisplayId(std::atoll(fields.displayIdItem->valuestring));
    serviceInfo.SetServiceOwnerTokenId(fields.serviceOwnerTokenIdItem->valueint);
    serviceInfo.SetServiceOwnerPkgName(fields.serviceOwnerPkgNameItem->valuestring);
    serviceInfo.SetServiceRegisterTokenId(fields.serviceRegisterTokenIdItem->valueint);
    serviceInfo.SetServiceId(std::atoll(fields.serviceIdItem->valuestring));
    serviceInfo.SetTimeStamp(std::atoll(fields.timeStampItem->valuestring));
    serviceInfo.SetPublishState(fields.publishStateItem->valueint);
    serviceInfo.SetServiceType(fields.serviceTypeItem->valuestring);
    serviceInfo.SetServiceName(fields.serviceNameItem->valuestring);
    serviceInfo.SetServiceDisplayName(fields.serviceDisplayNameItem->valuestring);
    serviceInfo.SetCustomData(fields.customDataItem->valuestring);
    serviceInfo.SetServiceCode(fields.serviceCodeItem->valuestring);
    serviceInfo.SetDataLen(fields.dataLenItem->valueint);
    serviceInfo.SetExtraData(fields.extraDataItem->valuestring);
    serviceInfo.SetVersion(fields.versionItem->valuestring);
    serviceInfo.SetDescription(fields.descriptionItem->valuestring);
}

int32_t ServiceInfoManager::DeleteSyncServiceInfo(std::vector<std::string> matchedKeys)
{
    {
        std::lock_guard<std::mutex> lock(syncStoreMutex_);
        if (syncServiceInfoKvAdapter_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }

        if (syncServiceInfoKvAdapter_->DeleteBatch(matchedKeys) != DP_SUCCESS) {
            HILOGE("Batch delete failed for %{public}zu entries", matchedKeys.size());
            return DP_DEL_KV_DB_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoManager::ProcessServiceInfoEntry(const std::string& key, const std::string& value,
    const UserInfo& userInfo, std::vector<ServiceInfo>& serviceInfos)
{
    cJSON *jsonObj = cJSON_Parse(value.c_str());
    if (jsonObj == nullptr) {
        HILOGE("Parse JSON failed for key: %{public}s", key.c_str());
        return DP_LOAD_JSON_FILE_FAIL;
    }

    ParsedJSONFields fields;
    if (!ParseAndValidateJSON(jsonObj, fields)) {
        cJSON_Delete(jsonObj);
        return DP_INVALID_PARAMS;
    }

    if (fields.udidItem && fields.udidItem->valuestring == userInfo.udid &&
        (userInfo.userId == DEFAULT_USER_ID || (fields.userIdItem && fields.userIdItem->valueint == userInfo.userId)) &&
        (userInfo.serviceId == DEFAULT_SERVICE_ID ||
            (fields.serviceIdItem && std::atoll(fields.serviceIdItem->valuestring) == userInfo.serviceId))) {
        ServiceInfo serviceInfo;
        FillServiceInfo(fields, serviceInfo);
        serviceInfos.push_back(serviceInfo);
    }

    cJSON_Delete(jsonObj);
    return DP_SUCCESS;
}
//delete start
int32_t ServiceInfoProfileManage::Init()
{
    HILOGI("call!");
    std::lock_guard<std::mutex> lock(storeMutex_);
    serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t ret = serviceInfoKvAdapter_->Init();
    if (ret != DP_SUCCESS) {
        HILOGE("ServiceInfoProfileManage init failed, ret: %{public}d", ret);
        return DP_INIT_DB_FAILED;
    }
    HILOGI("Init finish, ret: %{public}d", ret);
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        serviceInfoKvAdapter_->UnInit();
        serviceInfoKvAdapter_ = nullptr;
    }
    HILOGI("UnInit success");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t ServiceInfoProfileManage::PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGI("PutServiceInfoProfile: %{public}s", serviceInfoProfile.dump().c_str());
    int32_t userId = serviceInfoProfile.GetUserId();
    if (!ProfileUtils::IsSvrInfoProfileValid(serviceInfoProfile)) {
        HILOGE("the profile is invalid!");
        return DP_INVALID_PARAMS;
    }
    std::map<std::string, std::string> entries;
    ProfileUtils::ServiceInfoProfileToEntries(serviceInfoProfile, entries);
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("deviceProfileStore is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (serviceInfoKvAdapter_->PutBatch(entries) != DP_SUCCESS) {
            return DP_PUT_KV_DB_FAIL;
        }
    }
    HILOGD("PutServiceInfoProfile success");

    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId)
{
    HILOGI("regServiceId: %{public}d, userId %{public}d", regServiceId, userId);
    int32_t res = 0;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        res = ProfileControlUtils::DeleteServiceInfoProfile(serviceInfoKvAdapter_, regServiceId, userId);
    }
    if (res != DP_SUCCESS) {
        HILOGE("DeleteServiceInfoProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGD("DeleteServiceInfoProfile success");
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByServiceId(int64_t serviceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    if (serviceId == 0) {
        HILOGE("serviceId:%{public}" PRId64 " invalid", serviceId);
        return DP_INVALID_PARAMS;
    }
    HILOGI("serviceId:%{public}" PRId64, serviceId);
    std::map<std::string, std::string> allEntries;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t ret = serviceInfoKvAdapter_->GetByPrefix(SERVICE_INFO, allEntries);
        if (ret != DP_SUCCESS) {
            HILOGE("GetServiceInfoProfileByServiceId fail, ret: %{public}d", ret);
            return ret;
        }
    }
    std::string regServiceId = "";
    std::string serviceIdStr = std::to_string(serviceId);
    for (const auto& [key, value] : allEntries) {
        if (key.find(SERVICEID) == std::string::npos || value != serviceIdStr) {
            continue;
        }
        regServiceId = FindRegServiceId(key);
        if (!regServiceId.empty()) {
            break;
        }
    }
    if (regServiceId.empty()) {
        HILOGE("No match regServiceId.");
        return DP_NOT_FIND_DATA;
    }
    return GetServiceInfoProfileByRegServiceId(regServiceId, serviceInfoProfile);
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByRegServiceId(int32_t regServiceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    if (regServiceId == 0) {
        HILOGE("regServiceId:%{public}d invalid", regServiceId);
        return DP_INVALID_PARAMS;
    }
    HILOGI("regServiceId:%{public}d", regServiceId);
    return GetServiceInfoProfileByRegServiceId(std::to_string(regServiceId), serviceInfoProfile);
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByTokenId(int64_t tokenId,
    std::vector<ServiceInfoProfileNew>& serviceInfoProfiles)
{
    if (tokenId <= 0) {
        HILOGE("tokenId:%{public}" PRId64 " invalid", tokenId);
        return DP_INVALID_PARAMS;
    }
    HILOGI("tokenId:%{public}" PRId64, tokenId);
    std::map<std::string, std::string> allEntries;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t ret = serviceInfoKvAdapter_->GetByPrefix(SERVICE_INFO, allEntries);
        if (ret != DP_SUCCESS) {
            HILOGE("GetServiceInfoProfileByTokenId fail, ret: %{public}d", ret);
            return ret;
        }
    }
    std::string tokenIdStr = std::to_string(tokenId);
    std::unordered_set<std::string> regServiceIds;
    for (const auto& [key, value] : allEntries) {
        if (key.find(TOKENID) == std::string::npos || value != tokenIdStr) {
            continue;
        }
        std::string regServiceId = FindRegServiceId(key);
        if (regServiceId.empty()) {
            continue;
        }
        regServiceIds.insert(regServiceId);
    }
    if (regServiceIds.empty()) {
        HILOGE("No match regServiceId.");
        return DP_NOT_FIND_DATA;
    }
    for (const auto& regServiceId : regServiceIds) {
        ServiceInfoProfileNew serviceInfoProfile;
        if (GetServiceInfoProfileByRegServiceId(regServiceId, serviceInfoProfile) == DP_SUCCESS) {
            serviceInfoProfiles.emplace_back(serviceInfoProfile);
        }
    }
    if (serviceInfoProfiles.empty()) {
        HILOGE("serviceInfoProfiles is empty");
        return DP_NOT_FIND_DATA;
    }
    HILOGI("serviceInfoProfiles.size: %{public}zu", serviceInfoProfiles.size());
    return DP_SUCCESS;
}

std::string ServiceInfoProfileManage::FindRegServiceId(const std::string& str)
{
    size_t firstPos = str.find(SEPARATOR);
    if (firstPos == std::string::npos) {
        return "";
    }
    size_t secondPos = str.find(SEPARATOR, firstPos + 1);
    if (secondPos == std::string::npos) {
        return "";
    }
    return str.substr(firstPos + 1, secondPos - firstPos - 1);
}

int32_t ServiceInfoProfileManage::SetServiceInfoProfile(const std::string& regServiceId,
    const std::map<std::string, std::string>& finalSerProfile, ServiceInfoProfileNew& serviceInfoProfile)
{
    if (regServiceId.empty() || finalSerProfile.empty()) {
        HILOGE("params invalid");
        return DP_NOT_FIND_DATA;
    }
    std::string key = finalSerProfile.begin()->first;
    size_t lastPos = key.find_last_of(SEPARATOR);
    if (lastPos == std::string::npos) {
        HILOGE("key not found SEPARATOR");
        return DP_NOT_FIND_DATA;
    }
    std::string prefix = key.substr(0, lastPos + 1);
    const std::vector<std::string> requiredKeys = {prefix + PUBLISH_STATE, prefix + SERVICEID,
        prefix + TOKENID, prefix + RDB_USER_ID};
    for (const auto& requiredKey : requiredKeys) {
        if (finalSerProfile.find(requiredKey) == finalSerProfile.end()) {
            HILOGE("Key not found: %s", requiredKey.c_str());
            return DP_NOT_FIND_DATA;
        }
    }
    const auto& checkNum = [](const std::string& s) { return ProfileUtils::IsNumStr(s); };
    if (!checkNum(regServiceId) || !checkNum(finalSerProfile.at(prefix + PUBLISH_STATE)) ||
        !checkNum(finalSerProfile.at(prefix + SERVICEID)) || !checkNum(finalSerProfile.at(prefix + TOKENID)) ||
        !checkNum(finalSerProfile.at(prefix + RDB_USER_ID))) {
        HILOGE("Invalid number params");
        return DP_NOT_FIND_DATA;
    }
    serviceInfoProfile.SetRegServiceId(std::atoi(regServiceId.c_str()));
    serviceInfoProfile.SetDeviceId(finalSerProfile.count(prefix + DEVICE_ID)
        ? finalSerProfile.at(prefix + DEVICE_ID) : "");
    serviceInfoProfile.SetSerPubState(finalSerProfile.count(prefix + PUBLISH_STATE)
        ? std::atoi(finalSerProfile.at(prefix + PUBLISH_STATE).c_str()) : 0);
    serviceInfoProfile.SetServiceDisplayName(finalSerProfile.count(prefix + SERVICE_DISPLAY_NAME)
        ? finalSerProfile.at(prefix + SERVICE_DISPLAY_NAME) : "");
    serviceInfoProfile.SetServiceId(finalSerProfile.count(prefix + SERVICEID)
        ? std::atoll(finalSerProfile.at(prefix + SERVICEID).c_str()) : 0);
    serviceInfoProfile.SetServiceName(finalSerProfile.count(prefix + SERVICE_NAME)
        ? finalSerProfile.at(prefix + SERVICE_NAME) : "");
    serviceInfoProfile.SetServiceType(finalSerProfile.count(prefix + SERVICE_TYPE)
        ? finalSerProfile.at(prefix + SERVICE_TYPE) : "");
    serviceInfoProfile.SetTokenId(finalSerProfile.count(prefix + TOKENID)
        ? std::atoll(finalSerProfile.at(prefix + TOKENID).c_str()) : 0);
    serviceInfoProfile.SetUserId(finalSerProfile.count(prefix + RDB_USER_ID)
        ? std::atoi(finalSerProfile.at(prefix + RDB_USER_ID).c_str()) : -1);
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByRegServiceId(const std::string& regServiceIdStr,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    int32_t ret = DP_SUCCESS;
    std::map<std::string, std::string> allEntries;
    {
        std::lock_guard<std::mutex> lock(storeMutex_);
        if (serviceInfoKvAdapter_ == nullptr) {
            HILOGE("serviceInfoKvAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        ret = serviceInfoKvAdapter_->GetByPrefix(SERVICE_INFO + SEPARATOR + regServiceIdStr, allEntries);
        if (ret != DP_SUCCESS) {
            HILOGE("Get by regServiceId:%{public}s fail, ret: %{public}d", regServiceIdStr.c_str(), ret);
            return ret;
        }
    }
    ret = SetServiceInfoProfile(regServiceIdStr, allEntries, serviceInfoProfile);
    if (ret != DP_SUCCESS) {
        HILOGE("SetServiceInfoProfile failed");
        return ret;
    }
    HILOGI("serviceInfoProfile: %{public}s", serviceInfoProfile.dump().c_str());
    return DP_SUCCESS;
}
//delete end
//LCOV_EXCL_STOP
} // namespace DistributedDeviceProfile
} // namespace OHOS