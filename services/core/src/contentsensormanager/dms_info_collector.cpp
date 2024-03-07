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

#include "dms_info_collector.h"
#include "cJSON.h"
#include "dms_constant.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "DmsInfoCollector";
}

bool DmsInfoCollector::ConvertToProfile(std::vector<ServiceProfile>& svrProfileList)
{
    HILOGI("called!");
    ServiceProfile svrProfile;
    svrProfile.SetDeviceId(GetDeviceUdid());
    svrProfile.SetServiceName(DistributedSchedule::Constants::DMS_SERVICE_ID);
    svrProfile.SetServiceType(DistributedSchedule::Constants::DMS_SERVICE_ID);
    svrProfileList.push_back(svrProfile);
    return true;
}

bool DmsInfoCollector::ConvertToProfile(std::vector<CharacteristicProfile>& charProfileList)
{
    HILOGI("called!");
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(GetDeviceUdid());
    charProfile.SetServiceName(DistributedSchedule::Constants::DMS_SERVICE_ID);
    charProfile.SetCharacteristicKey(DistributedSchedule::Constants::DMS_CHAR_ID);
    cJSON* jsonData = cJSON_CreateObject();
    if(!cJSON_IsObject(jsonData)) {
        cJSON_Delete(jsonData);
        HILOGE("Create cJSON failed!");
        return false;
    }
    cJSON* item = cJSON_AddStringToObject(jsonData, DistributedSchedule::Constants::PACKAGE_NAMES, 
        DistributedSchedule::Constants::DMS_NAME);
    if (!cJSON_IsString(item)) {
        HILOGE("Add PACKAGE_NAMES to cJSON failed!");
        cJSON_Delete(jsonData);
        return false;
    }
    item = cJSON_AddStringToObject(jsonData, DistributedSchedule::Constants::VERSIONS, 
        DistributedSchedule::Constants::DMS_VERSION);
    if (!cJSON_IsString(item)) {
        HILOGE("Add VERSIONS to cJSON failed!");
        cJSON_Delete(jsonData);
        return false;
    }
    char* jsonChars = cJSON_PrintUnformatted(jsonData);
    if (jsonChars == NULL) {
        cJSON_Delete(jsonData);
        HILOGE("cJSON formatted to string failed!");
        return false;
    }
    std::string jsonStr = jsonChars;
    charProfile.SetCharacteristicValue(jsonStr);
    cJSON_Delete(jsonData);
    free(jsonChars);
    charProfileList.push_back(charProfile);
    return true;
}

std::string DmsInfoCollector::GetDeviceUdid()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
}
} // namespace DeviceProfile
} // namespace OHOS