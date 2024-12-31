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

#ifndef OHOS_DP_SERVICE_PROFILE_DAO_H
#define OHOS_DP_SERVICE_PROFILE_DAO_H

#include "values_bucket.h"

#include "profile_data_rdb_adapter.h"
#include "service_profile.h"
#include "service_profile_filter_opotions.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceProfileDao {
    DECLARE_SINGLE_INSTANCE(ServiceProfileDao);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutServiceProfile(ServiceProfile& serviceProfile);
    int32_t DeleteServiceProfile(const ServiceProfile& serviceProfile);
    int32_t UpdateServiceProfile(const ServiceProfile& serviceProfile);
    int32_t GetServiceProfiles(const ServiceProfileFilterOptions& filterOptions,
        std::vector<ServiceProfile>& serviceProfiles);
private:
    int32_t CreateTable();
    int32_t CreateIndex();
    int32_t ConvertToServiceProfile(std::shared_ptr<ResultSet> resultSet, ServiceProfile& serviceProfile);
    int32_t CreateQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions, std::string& sql,
        std::vector<ValueObject>& condition);
    void CreateBaseQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions, std::string& whereSql,
        std::vector<ValueObject>& condition);
    void CreateComplexQuerySqlAndCondition(const ServiceProfileFilterOptions& filterOptions, std::string& whereSql,
        std::vector<ValueObject>& condition);
    void ServiceProfileToEntries(const ServiceProfile& serviceProfile, ValuesBucket& values);
    int32_t SetServiceProfileId(ServiceProfile& serviceProfile);
};


} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_PROFILE_DAO_H
