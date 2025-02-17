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

#ifndef OHOS_DP_SERVICE_INFO_PROFILE_MANAGER_H
#define OHOS_DP_SERVICE_INFO_PROFILE_MANAGER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "kvstore_observer.h"
#include "values_bucket.h"

#include "service_info_profile.h"
#include "service_info_rdb_adapter.h"
#include "service_info_unique_key.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;
class ServiceInfoProfileManager {
    DECLARE_SINGLE_INSTANCE(ServiceInfoProfileManager);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile);
    int32_t DeleteServiceInfoProfile(const ServiceInfoUniqueKey& key);
    int32_t UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile);
    int32_t GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key, ServiceInfoProfile& serviceInfoProfile);
    int32_t GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    int32_t GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles);
private:
    int32_t ConvertToServiceInfo(std::shared_ptr<ResultSet> resultSet, ServiceInfoProfile& serviceInfo);
    int32_t ServiceInfoProfileToEntries(const ServiceInfoProfile& serviceInfo, ValuesBucket& values);
    int32_t CreateTable();
    int32_t CreateIndex();

private:
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_SERVICE_INFO_PROFILE_MANAGER_H
