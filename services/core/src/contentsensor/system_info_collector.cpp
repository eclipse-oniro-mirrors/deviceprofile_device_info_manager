/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "system_info_collector.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"

#include "nlohmann/json.hpp"
#include "parameters.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SystemInfoCollector";

const std::string SERVICE_ID = "system";
const std::string SERVICE_TYPE = "system";
const std::string EMPTY_PARAM = "";
const std::string SYSTEM_OS_TYPE = "type";
const std::string DEVICE_OHOS_VERSION = "harmonyVersion";
const std::string DEVICE_API_LEVEL = "harmonyApiLevel";
const std::string DEVICE_OHOS_NAME = "OpenHarmony";
const std::string DEVICE_API_LEVEL_PARAM = "hw_sc.build.os.apiversion";
const std::string DEVICE_OHOS_VERSION_PARAM = "hw_sc.build.os.version";
const std::string DEVICE_OHOS_NAME_PARAM = "const.ohos.name";
constexpr int32_t OHOS_TYPE_UNKNOWN = -1;
constexpr int32_t OHOS_TYPE = 10;
}

void SystemInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    jsonData[SYSTEM_OS_TYPE] = GetOsType();
    jsonData[DEVICE_OHOS_VERSION] = GetOsVersion();
    jsonData[DEVICE_API_LEVEL] = GetApiVersion();
    profile.SetCharacteristicProfileJson(jsonData.dump());
}

int32_t SystemInfoCollector::GetOsType()
{
    if (system::GetParameter(DEVICE_OHOS_NAME_PARAM, EMPTY_PARAM) == DEVICE_OHOS_NAME) {
        return OHOS_TYPE;
    }
    return OHOS_TYPE_UNKNOWN;
}

std::string SystemInfoCollector::GetApiVersion()
{
    return system::GetParameter(DEVICE_API_LEVEL_PARAM, EMPTY_PARAM);
}

std::string SystemInfoCollector::GetOsVersion()
{
    return system::GetParameter(DEVICE_OHOS_VERSION_PARAM, EMPTY_PARAM);
}
} // namespace DeviceProfile
} // namespace OHOS