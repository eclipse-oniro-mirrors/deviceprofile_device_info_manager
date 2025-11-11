/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "service_info_profile_new.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "kv_data_change_listener.h"
#include "kv_store_death_recipient.h"
#include "kv_sync_completed_listener.h"
#include "profile_control_utils.h"

#include "multi_user_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoProfileManage)

namespace {
    const std::string STORE_ID = "dp_kv_store_service_info_profile";
    const std::string TAG = "ServiceInfoProfileManage";
}
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
    serviceInfoProfile.SetRegServiceId(std::stoi(regServiceId));
    serviceInfoProfile.SetDeviceId(finalSerProfile.count(prefix + DEVICE_ID)
        ? finalSerProfile.at(prefix + DEVICE_ID) : "");
    serviceInfoProfile.SetSerPubState(finalSerProfile.count(prefix + PUBLISH_STATE)
        ? std::stoi(finalSerProfile.at(prefix + PUBLISH_STATE)) : 0);
    serviceInfoProfile.SetServiceDisplayName(finalSerProfile.count(prefix + SERVICE_DISPLAY_NAME)
        ? finalSerProfile.at(prefix + SERVICE_DISPLAY_NAME) : "");
    serviceInfoProfile.SetServiceId(finalSerProfile.count(prefix + SERVICEID)
        ? std::stoll(finalSerProfile.at(prefix + SERVICEID)) : 0);
    serviceInfoProfile.SetServiceName(finalSerProfile.count(prefix + SERVICE_NAME)
        ? finalSerProfile.at(prefix + SERVICE_NAME) : "");
    serviceInfoProfile.SetServiceType(finalSerProfile.count(prefix + SERVICE_TYPE)
        ? finalSerProfile.at(prefix + SERVICE_TYPE) : "");
    serviceInfoProfile.SetTokenId(finalSerProfile.count(prefix + TOKENID)
        ? std::stoll(finalSerProfile.at(prefix + TOKENID)) : 0);
    serviceInfoProfile.SetUserId(finalSerProfile.count(prefix + RDB_USER_ID)
        ? std::stoi(finalSerProfile.at(prefix + RDB_USER_ID)) : -1);
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
//LCOV_EXCL_STOP
} // namespace DistributedDeviceProfile
} // namespace OHOS