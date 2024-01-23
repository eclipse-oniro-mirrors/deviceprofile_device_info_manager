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

#include "pasteboard_info_collector.h"

#include "device_profile_log.h"
#include "nlohmann/json.hpp"
#include "parameter.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "PasteboardInfoCollector";
const std::string SERVICE_ID = "pasteboardService";
const std::string SERVICE_TYPE = "pasteboardService";
const std::string SUPPORT_DISTRIBUTED_PASTEBOARD = "supportDistributedPasteboard";
const std::string PASTEBOARD_VERSION = "PasteboardVersionId";
constexpr uint32_t FIRST_VERSION = 4;

const char *DISTRIBUTED_PASTEBOARD_ENABLED_KEY = "persist.pasteboard.distributedPasteboardEnabled";
const std::string ENABLED_STATUS = "true";
const char* UNDEFINED_VALUE = "undefined";
constexpr int CONFIG_LEN = 10;
}

bool PasteboardInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    HILOGI("call");
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    jsonData[SUPPORT_DISTRIBUTED_PASTEBOARD] = GetSurportDistributedPasteboard();
    jsonData[PASTEBOARD_VERSION] = FIRST_VERSION;
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}

bool PasteboardInfoCollector::GetSurportDistributedPasteboard()
{
    char value[CONFIG_LEN] = { 0 };
    GetParameter(DISTRIBUTED_PASTEBOARD_ENABLED_KEY, UNDEFINED_VALUE, value, CONFIG_LEN);
    HILOGI("GetParameter, value = %{public}s.", value);
    std::string enabledStatus(value);
    return enabledStatus == ENABLED_STATUS;
}
} // namespace DeviceProfile
} // OHOS