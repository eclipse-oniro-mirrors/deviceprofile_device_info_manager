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

#ifndef OHOS_DP_DEVICE_PROFILE_DAO_H
#define OHOS_DP_DEVICE_PROFILE_DAO_H


#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <vector>

#include "device_profile.h"
#include "device_profile_filter_options.h"
#include "profile_data_rdb_adapter.h"
#include "single_instance.h"
#include "values_bucket.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class DeviceProfileDao {
    DECLARE_SINGLE_INSTANCE(DeviceProfileDao);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutDeviceProfile(const DeviceProfile& deviceProfile);
    int32_t GetDeviceProfiles(const DeviceProfileFilterOptions& filterOptions,
        std::vector<DeviceProfile>& deviceProfiles);
    int32_t DeleteDeviceProfile(const DeviceProfile& deviceProfile);
    int32_t UpdateDeviceProfile(const DeviceProfile& newProfile);
    int32_t CreateTable();
    int32_t CreateIndex();
    void CreateQuerySqlAndCondition(const DeviceProfileFilterOptions& filterOptions,
        std::string& sql, std::vector<ValueObject>& condition);
    int32_t DeviceProfileToEntries(const DeviceProfile& deviceProfile, ValuesBucket& values);
    int32_t ConvertToDeviceProfile(std::shared_ptr<ResultSet> resultSet, DeviceProfile& deviceProfile);
    void GenerateSqlAndCondition(const std::vector<int32_t>& params,
        std::string& sql, std::vector<ValueObject>& condition);
    void GenerateSqlAndCondition(const std::vector<std::string>& params,
        std::string& sql, std::vector<ValueObject>& condition);
private:
    std::mutex rdbMutex_;
};
}
}
#endif // OHOS_DP_DEVICE_PROFILE_DAO_H
