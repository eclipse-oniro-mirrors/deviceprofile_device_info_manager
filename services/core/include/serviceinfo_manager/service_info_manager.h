/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_SERVICE_INFO_MANAGER_H
#define OHOS_DP_SERVICE_INFO_MANAGER_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "service_info.h"
//delete start
#include "service_info_profile_new.h"
//delete end
#include "service_info_kv_adapter.h"
#include "distributed_device_profile_constants.h"
#include "single_instance.h"
#include "user_info.h"
#include "kv_adapter.h"
#include "cJSON.h"

namespace OHOS {
namespace DistributedDeviceProfile {
    //delete start
class ServiceInfoProfileManage {
DECLARE_SINGLE_INSTANCE(ServiceInfoProfileManage);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    int32_t PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfoProfile);
    int32_t DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId = DEFAULT_USER_ID);
    int32_t UpdateServiceInfoProfile(int32_t regServiceId, const ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfileNew>& serviceInfoProfileList);
    int32_t GetServiceInfoProfileByServiceId(int64_t serviceId, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByRegServiceId(int32_t regServiceId, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByTokenId(int64_t tokenId, std::vector<ServiceInfoProfileNew>& serviceInfoProfiles);
private:
    std::string FindRegServiceId(const std::string& str);
    int32_t SetServiceInfoProfile(const std::string& regServiceId,
        const std::map<std::string, std::string>& finalSerProfile, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByRegServiceId(const std::string& regServiceIdStr,
        ServiceInfoProfileNew& serviceInfoProfile);
    std::mutex storeMutex_;
    std::shared_ptr<ServiceInfoKvAdapter> serviceInfoKvAdapter_ = nullptr;
};
    //delete end
    struct ParsedJSONFields {
        cJSON* udidItem;
        cJSON* userIdItem;
        cJSON* serviceIdItem;
        cJSON* displayIdItem;
        cJSON* serviceOwnerTokenIdItem;
        cJSON* serviceOwnerPkgNameItem;
        cJSON* serviceRegisterTokenIdItem;
        cJSON* timeStampItem;
        cJSON* publishStateItem;
        cJSON* serviceTypeItem;
        cJSON* serviceNameItem;
        cJSON* serviceDisplayNameItem;
        cJSON* customDataItem;
        cJSON* serviceCodeItem;
        cJSON* dataLenItem;
        cJSON* extraDataItem;
        cJSON* versionItem;
        cJSON* descriptionItem;
    };
class ServiceInfoManager {
DECLARE_SINGLE_INSTANCE(ServiceInfoManager);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    int32_t PutServiceInfo(const ServiceInfo& serviceInfo);
    int32_t DeleteServiceInfo(const UserInfo& userInfo);
    int32_t GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfoList);
    int32_t GetServiceInfosByUserInfo(const UserInfo& userInfo, std::vector<ServiceInfo>& serviceInfos);
    std::vector<DistributedKv::Entry> GetEntriesByKeys(const std::vector<std::string>& keys);
    bool IsKeyMatch(const std::string& remaining, const UserInfo& userInfo);
    bool ParseAndValidateJSON(cJSON* jsonObj, ParsedJSONFields& fields);
    void FillServiceInfo(const ParsedJSONFields& fields, ServiceInfo& serviceInfo);
    int32_t DeleteSyncServiceInfo(std::vector<std::string> matchedKeys);

private:
    std::mutex storeMutex_;
    std::mutex syncStoreMutex_;
    std::shared_ptr<ServiceInfoKvAdapter> serviceInfoKvAdapter_ = nullptr;
    std::shared_ptr<KVAdapter> syncServiceInfoKvAdapter_ = nullptr;

    int32_t ProcessServiceInfoEntry(const std::string& key, const std::string& value, const UserInfo& userInfo,
        std::vector<ServiceInfo>& serviceInfos);
    bool ValidateStringFields(const ParsedJSONFields& fields);
    bool ValidateNumberFields(const ParsedJSONFields& fields);
    bool IsStringFieldValid(const cJSON* item);
};
} // DistributedDeviceKVAdapterProfile
} // OHOS
#endif // OHOS_DP_SERVICE_INFO_MANAGER_H