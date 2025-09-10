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
    std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
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
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
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
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
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
    HILOGI("regServiceId: %{public}s, userId %{public}d", ProfileUtils::GetAnonyInt32(regServiceId).c_str(), userId);
    int32_t res = 0;
    res = ProfileControlUtils::DeleteServiceInfoProfile(serviceInfoKvAdapter_, regServiceId, userId);
    if (res != DP_SUCCESS) {
        HILOGE("DeleteServiceInfoProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGD("DeleteServiceInfoProfile success");
    return DP_SUCCESS;
}
 
int32_t ServiceInfoProfileManage::GetAllServiceInfoProfileList(
    std::vector<ServiceInfoProfileNew>& serviceInfoProfileList)
{
    return DP_SUCCESS;
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByServiceId(int64_t serviceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGE("serviceId:%{public}s", ProfileUtils::GetAnonyInt32(serviceId).c_str());
    std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
    if (serviceInfoKvAdapter_ == nullptr) {
        HILOGE("serviceInfoKvAdapter_ is nullptr");
        return DP_KV_DB_PTR_NULL;
    }
    std::map<std::string, std::string> allEntries;
    int32_t ret = serviceInfoKvAdapter_->GetByPrefix("serviceInfo", allEntries);
    if (ret != DP_SUCCESS) {
        HILOGE("GetServiceInfoProfileByServiceId fail, ret: %{public}d", ret);
        return ret;
    }
    std::string regServiceId = "";
    std::map<std::string, std::string> allServiceIdEntries;
    for (const auto& pair : allEntries) {
        if (pair.first.find("serviceId") != std::string::npos) {
            allServiceIdEntries.insert(pair);
        }
    }
    for (const auto& pair : allServiceIdEntries) {
        if (pair.second == std::to_string(serviceId)) {
            regServiceId = FindRegServiceId(pair.first);
        }
    }
    if (regServiceId.empty) {
        HILOGE("No match regServiceId.")
        return DP_NOT_FOUND_DATA;
    }
    std::string finalPrefix = SERVICE_INFO + SEPARATOR +regServiceId;
    std::map<std::string, std::string> profileEntries;
    ret = serviceInfoKvAdapter_->GetByPrefix(finalPrefix, profileEntries);
    if (ret != DP_SUCCESS) {
        HILOGE("GetByPrefix fail, ret: %{public}d", ret);
        return ret;
    }
    SetServiceInfoProfile(regServiceId, profileEntries, serviceInfoProfile);
    HILOGI("serviceInfoProfile: %{public}s", serviceInfoProfile.dump().c_str());
    return DP_SUCCESS;
}

void ServiceInfoProfileManage::SetServiceInfoProfile(const std::string& regServiceId,
    const std::map<std::string, std::string>& finalSerProfile, ServiceInfoProfileNew& serviceInfoProfile)
{
    std::string key = finalSerProfile.begin()->first;
    size_t lastPos = key.find_last_of(SEPARATOR);
    std::string prefix = key.substr(0, lastPos + 1);
    int32_t regServiceIdTempOne = std::stoi(regServiceId);
    std::string regDeviceIdTemp = finalSerProfile.count(prefix + "deviceId")
        ? finalSerProfile.at(prefix + "deviceId") : "";
    int8_t regSerPubStateTemp = finalSerProfile.count(prefix + "publishState")
        ? std::stoi(finalSerProfile.at(prefix + "publishState")) : 0;
    std::string regServiceDisplayNameTemp = finalSerProfile.count(prefix + "serviceDisplayName")
        ? finalSerProfile.at(prefix + "serviceDisplayName") : "";
    int64_t regServiceIdTemp = finalSerProfile.count(prefix + "serviceId")
        ? std::stoll(finalSerProfile.at(prefix + "serviceId")) : 0;
    std::string regSetServiceNameTemp = finalSerProfile.count(prefix + "serviceName")
        ? finalSerProfile.at(prefix + "serviceName") : "";
    std::string regServiceTypeTemp = finalSerProfile.count(prefix + "serviceType")
        ? finalSerProfile.at(prefix + "serviceType") : "";
    int64_t regTokenIdTemp = finalSerProfile.count(prefix + "tokenId")
        ? std::stoll(finalSerProfile.at(prefix + "tokenId")) : 0;
    int32_t regUserIdTemp = finalSerProfile.count(prefix + "userId")
        ? std::stoi(finalSerProfile.at(prefix + "userId")) : 0;
 
    serviceInfoProfile.SetRegServiceId(regServiceIdTempOne);
    serviceInfoProfile.SetDeviceId(regDeviceIdTemp);
    serviceInfoProfile.SetSerPubState(regSerPubStateTemp);
    serviceInfoProfile.SetServiceDisplayName(regServiceDisplayNameTemp);
    serviceInfoProfile.SetServiceId(regServiceIdTemp);
    serviceInfoProfile.SetServiceName(regSetServiceNameTemp);
    serviceInfoProfile.SetServiceType(regServiceTypeTemp);
    serviceInfoProfile.SetTokenId(regTokenIdTemp);
    serviceInfoProfile.SetUserId(regUserIdTemp);
}

int32_t ServiceInfoProfileManage::GetServiceInfoProfileByTokenId(int64_t tokenId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGE("tokenId:%{public}s", ProfileUtils::GetAnonyInt32(tokenId).c_str());
    std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
    if (serviceInfoKvAdapter_ == nullptr) {
        HILOGE("serviceInfoKvAdapter_ is nullptr");
        return DP_KV_DB_PTR_NULL;
    }
    std::map<std::string, std::string> allEntries;
    int32_t ret = serviceInfoKvAdapter_->GetByPrefix("serviceInfo", allEntries);
    if (ret != DP_SUCCESS) {
        HILOGE("GetServiceInfoProfileByTokenId fail, ret: %{public}d", ret);
        return ret;
    }
    std::string regServiceId = "";
    std::map<std::string, std::string> allServiceIdEntries;
    for (const auto& pair : allEntries) {
        if (pair.first.find("tokenId") != std::string::npos) {
            allServiceIdEntries.insert(pair);
        }
    }
    for (const auto& pair : allServiceIdEntries) {
        if (pair.second == std::to_string(tokenId)) {
            regServiceId = FindRegServiceId(pair.first);
        }
    }
    if (regServiceId.empty) {
        HILOGE("No match regServiceId.")
        return DP_NOT_FOUND_DATA;
    }
    std::string finalPrefix = SERVICE_INFO + SEPARATOR +regServiceId;
    std::map<std::string, std::string> profileEntries;
    ret = serviceInfoKvAdapter_->GetByPrefix(finalPrefix, profileEntries);
    if (ret != DP_SUCCESS) {
        HILOGE("GetByPrefix fail, ret: %{public}d", ret);
        return ret;
    }
    SetServiceInfoProfile(regServiceId, profileEntries, serviceInfoProfile);
    HILOGI("serviceInfoProfile: %{public}s", serviceInfoProfile.dump().c_str());
    return DP_SUCCESS;
}

std::string ServiceInfoProfileManage::FindRegServiceId(const std::string& str)
{
    size_t firstPos = str.find('#');
    if (firstPos == std::string::npos) {
        return "";
    }
    size_t secondPos = str.find('#', firstPos + 1);
    if (secondPos == std::string::npos) {
        return "";
    }
    return str.substr(firstPos + 1, secondPos - firstPos - 1);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS