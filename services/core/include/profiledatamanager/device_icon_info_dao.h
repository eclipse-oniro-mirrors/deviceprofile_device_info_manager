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

#ifndef OHOS_DP_DEVICE_ICON_INFO_DAO_H
#define OHOS_DP_DEVICE_ICON_INFO_DAO_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "device_icon_info.h"
#include "device_icon_info_filter_options.h"
#include "profile_data_rdb_adapter.h"
#include "single_instance.h"
#include "values_bucket.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class DeviceIconInfoDao {
    DECLARE_SINGLE_INSTANCE(DeviceIconInfoDao);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutDeviceIconInfo(const DeviceIconInfo& deviceIconInfo);
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos);
    int32_t DeleteDeviceIconInfo(const DeviceIconInfo& deviceIconInfo);
    int32_t UpdateDeviceIconInfo(const DeviceIconInfo& deviceIconInfo);
    int32_t CreateTable();
    int32_t CreateIndex();
    bool CreateQuerySqlAndCondition(const DeviceIconInfoFilterOptions& filterOptions,
        std::string& sql, std::vector<ValueObject>& condition);
    int32_t DeviceIconInfoToEntries(const DeviceIconInfo& deviceIconInfo, ValuesBucket& values);
    int32_t ConvertToDeviceIconInfo(std::shared_ptr<ResultSet> resultSet, DeviceIconInfo& deviceIconInfo);
private:
    std::mutex rdbMutex_;
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_DEVICE_ICON_INFO_DAO_H