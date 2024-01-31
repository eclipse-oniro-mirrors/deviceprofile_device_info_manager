/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "collaboration_info_collector.h"
#include "content_sensor_manager_utils.h"
#include "device_profile_manager.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "CollaborationInfoCollector";
const std::vector<std::string> COLLABORATION_SERVICE_ID_VECTOR = { "distributeCameraControllerService",
    "multiScreenAssistantService", "padCarCollaborate" };
const std::string COLLABORATION_CHARACTERISTIC_KEY = "status";
const std::string COLLABORATION_CHARACTERISTIC_VALUE = "false";
}

bool CollaborationInfoCollector::ConvertToProfile(std::vector<ServiceProfile> &svrProfileList)
{
    HILOGI("called!");
    auto deviceId = GetDeviceUdid();
    for (auto it = COLLABORATION_SERVICE_ID_VECTOR.begin(); it != COLLABORATION_SERVICE_ID_VECTOR.end(); it++) {
        ServiceProfile svrProfile;
        if (DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, *it, svrProfile) == DP_SUCCESS) {
            continue;
        }
        svrProfile.SetDeviceId(deviceId);
        svrProfile.SetServiceName(*it);
        svrProfile.SetServiceType(*it);
        svrProfileList.push_back(svrProfile);
    }
    return true;
}

bool CollaborationInfoCollector::ConvertToProfile(std::vector<CharacteristicProfile> &charProfileList)
{
    HILOGI("called!");
    auto deviceId = GetDeviceUdid();
    for (auto it = COLLABORATION_SERVICE_ID_VECTOR.begin(); it != COLLABORATION_SERVICE_ID_VECTOR.end(); it++) {
        CharacteristicProfile charProfile;
        if (DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, *it,
            COLLABORATION_CHARACTERISTIC_KEY, charProfile) == DP_SUCCESS) {
            continue;
        }
        charProfile.SetDeviceId(deviceId);
        charProfile.SetServiceName(*it);
        charProfile.SetCharacteristicKey(COLLABORATION_CHARACTERISTIC_KEY);
        charProfile.SetCharacteristicValue(COLLABORATION_CHARACTERISTIC_VALUE);
        charProfileList.push_back(charProfile);
    }
    return true;
}

std::string CollaborationInfoCollector::GetDeviceUdid()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
}
} // namespace DeviceProfile
} // namespace OHOS