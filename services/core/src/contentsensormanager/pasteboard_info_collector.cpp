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
#include "cJSON.h"
#include "parameter.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "PasteboardInfoCollector";
constexpr const char *SERVICE_ID = "pasteboardService";
constexpr const char *CHARACTER_ID = "supportDistributedPasteboard";
constexpr const char *VERSION_ID = "PasteboardVersionId";
constexpr uint32_t FIRST_VERSION = 4;

const char *DISTRIBUTED_PASTEBOARD_ENABLED_KEY = "persist.pasteboard.distributedPasteboardEnabled";
const std::string ENABLED_STATUS = "true";
const char* UNDEFINED_VALUE = "undefined";
constexpr int CONFIG_LEN = 10;
constexpr uint32_t NOT_SUPPORT = 0;
constexpr uint32_t SUPPORT = 1;
}

bool PasteboardInfoCollector::ConvertToProfile(std::vector<ServiceProfile>& svrProfileList)
{
    HILOGI("called!");
    ServiceProfile svrProfile;
    svrProfile.SetDeviceId(ContentSensorManagerUtils::GetInstance().ObtainLocalUdid());
    svrProfile.SetServiceName(SERVICE_ID);
    svrProfile.SetServiceType(SERVICE_ID);
    svrProfileList.push_back(svrProfile);
    return true;
}

bool PasteboardInfoCollector::ConvertToProfile(std::vector<CharacteristicProfile>& charProfileList)
{
    HILOGI("called!");
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(ContentSensorManagerUtils::GetInstance().ObtainLocalUdid());
    charProfile.SetServiceName(SERVICE_ID);
    charProfile.SetCharacteristicKey(CHARACTER_ID);

    cJSON *jsonData = cJSON_CreateObject();
    cJSON_AddNumberToObject(jsonData, CHARACTER_ID, GetSupportDistributedPasteboard());
    cJSON_AddNumberToObject(jsonData, VERSION_ID, FIRST_VERSION);
    charProfile.SetCharacteristicValue(cJSON_PrintUnformatted(jsonData));
    cJSON_Delete(jsonData);
    charProfileList.push_back(charProfile);
    return true;
}

uint32_t PasteboardInfoCollector::GetSupportDistributedPasteboard()
{
    char value[CONFIG_LEN] = { 0 };
    GetParameter(DISTRIBUTED_PASTEBOARD_ENABLED_KEY, UNDEFINED_VALUE, value, CONFIG_LEN);
    HILOGI("GetParameter, value = %{public}s.", value);
    std::string enabledStatus(value);
    return enabledStatus == ENABLED_STATUS ? SUPPORT : NOT_SUPPORT;
}
} // namespace DeviceProfile
} // OHOS