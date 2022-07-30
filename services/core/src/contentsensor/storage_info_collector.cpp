/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "storage_info_collector.h"

#include <sys/statvfs.h>

#include "device_profile_log.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "StorageInfoCollector";

const char* PATH_DATA = "/data";
const std::string SERVICE_ID = "storage";
const std::string SERVICE_TYPE = "storage";
const std::string CAPACITY = "capacity";
constexpr int64_t KILOBYTE = 1024;
}

bool StorageInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    int64_t totalSize = GetTotalSize();
    if (totalSize == 0) {
        return false;
    }
    jsonData[CAPACITY] = totalSize;
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}

int64_t StorageInfoCollector::GetTotalSize()
{
    int64_t totalSize = 0;
    struct statvfs diskInfo;
    int ret = statvfs(PATH_DATA, &diskInfo);
    if (ret != 0) {
        HILOGE("GetTotalSize failed");
        return totalSize;
    }
    totalSize =  (int64_t)diskInfo.f_bsize * (int64_t)diskInfo.f_blocks / KILOBYTE;
    return totalSize;
}
} // namespace DeviceProfile
} // OHOS
