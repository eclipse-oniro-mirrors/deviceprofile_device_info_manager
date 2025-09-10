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
 
#ifndef OHOS_DP_SERVICE_INFO_MANAGER_H
#define OHOS_DP_SERVICE_INFO_MANAGER_H
 
#include <cstdint>
#include <memory>
#include <mutex>
 
#include "service_info_profile_new.h"
#include "service_info_kv_adapter.h"
#include "distributed_device_profile_constants.h"
#include "single_instance.h"
 
namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoProfileManage {
DECLARE_SINGLE_INSTANCE(ServiceInfoProfileManage);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    int32_t PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfoProfile);
    int32_t DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId = DEFAULT_USER_ID);
    int32_t UpdateServiceInfoProfile(const int32_t regServiceId, const ServiceInfoProfileNew &serviceInfoProfile);
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfileNew>& serviceInfoProfileList);
    int32_t GetServiceInfoProfileByServiceId(int64_t serviceId, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByRegServiceId(const int32_t &regServiceId, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByTokenId(int64_t tokenId, ServiceInfoProfileNew& serviceInfoProfile);
 
    void RemoveSubstrings(std::string& str, const std::string& substr);
    void RemoveAfterSecondHash(std::string& str);
    int32_t SetServiceInfoProfile(const std::string& regServiceId,
    const std::map<std::string, std::string>& finalSerProfile, ServiceInfoProfileNew& serviceInfoProfile);
 
private:
    std::string FindRegServiceId(const std::string& str);
    std::shared_ptr<ServiceInfoKvAdapter> serviceInfoKvAdapter_ = nullptr;
    std::mutex dynamicStoreMutex_;
    std::atomic<bool> isFirst_{true};
    std::map<std::string, std::string> putTempCache_;
    std::mutex putTempCacheMutex_;
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_SERVICE_INFO_MANAGER_H