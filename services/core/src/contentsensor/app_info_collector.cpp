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

#include "app_info_collector.h"

#include "device_profile_log.h"
#include "distributed_ability_manager_interface.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DeviceInfoCollector";

const std::string SERVICE_ID = "appInfo";
const std::string SERVICE_TYPE = "appInfo";
const std::string PACKAGE_NAMES = "packageNames";
const std::string VERSIONS = "versions";
}

bool AppInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    std::string packageNames;
    std::string versions;
    GetDmsVersionInfo(packageNames, versions);
    jsonData[PACKAGE_NAMES] = packageNames;
    jsonData[VERSIONS] = versions;
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}

bool AppInfoCollector::GetDmsVersionInfo(std::string& dmsName, std::string& dmsVersionData)
{
    dmsName = DistributedSchedule::DMS_NAME;
    dmsVersionData = DistributedSchedule::DMS_VERSION;
    return true;
}
} // namespace DeviceProfile
} // OHOS
