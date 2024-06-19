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

#include "switch_status_collector.h"
#include <fstream>
#include "cJSON.h"
#include "config_policy_utils.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "profile_cache.h"
#include "profile_utils.h"
#include "switch_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "SwitchStatusCollector";
const std::string APP_ID = "distributed_device_profile_service";
}

bool SwitchStatusCollector::ConvertToProfile(std::vector<CharacteristicProfile>& charProfileList)
{
    HILOGI("call!");
    std::string fileContent = "";
    int32_t loadJsonResult = LoadJsonFile(SWITCH_CAPABILITY_PATH, fileContent);
    if (loadJsonResult != DP_SUCCESS) {
        HILOGE("Load json failed, result: %{public}d!", loadJsonResult);
        return false;
    }
    cJSON* switchCapabilityJson = cJSON_Parse(fileContent.c_str());
    if (!cJSON_IsObject(switchCapabilityJson)) {
        HILOGE("Switch capability json parse failed!");
        cJSON_Delete(switchCapabilityJson);
        return false;
    }
    // the charProfileList will be write to dynamic kv_store by ContentSensorManager
    // so, create anther vector of ChararcteristicProfile
    std::vector<CharacteristicProfile> switchCharProfileList;
    int32_t generateProfilesRes = GenerateSwitchProfiles(switchCapabilityJson, switchCharProfileList);
    if (generateProfilesRes != DP_SUCCESS) {
        HILOGE("Generate switch profiles result %{public}d!", generateProfilesRes);
        cJSON_Delete(switchCapabilityJson);
        return false;
    }
    HILOGI("Convert to profile success!");
    cJSON_Delete(switchCapabilityJson);
    AddSwitchStatusToDB(switchCharProfileList);
    return true;
}

int32_t SwitchStatusCollector::LoadJsonFile(const std::string& filePath, std::string& fileContent)
{
    HILOGI("call!");
    if (filePath.empty() || filePath.size() > MAX_STRING_LEN) {
        HILOGE("filePath is invalid!");
        return DP_INVALID_PARAM;
    }
    char buf[MAX_PATH_LEN] = {0};
    char targetPath[PATH_MAX + 1] = {0x00};
    char *srcPath = GetOneCfgFile(filePath.c_str(), buf, MAX_PATH_LEN);
    if (srcPath == nullptr) {
        HILOGE("srcPath is invalid!");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    if (strlen(srcPath) == 0 || strlen(srcPath) > PATH_MAX || realpath(srcPath, targetPath) == nullptr) {
        HILOGE("File canonicalization failed!");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    std::ifstream ifs(targetPath);
    if (!ifs.is_open()) {
        HILOGE("load json file failed");
        return DP_LOAD_JSON_FILE_FAIL;
    }
    fileContent = std::string(std::istreambuf_iterator<char>{ifs}, std::istreambuf_iterator<char>{});
    ifs.close();
    return DP_SUCCESS;
}

int32_t SwitchStatusCollector::GenerateSwitchProfiles(const cJSON* const staticInfoJson,
    std::vector<CharacteristicProfile>& charProfileList)
{
    if (!cJSON_IsObject(staticInfoJson)) {
        HILOGE("staticInfoJson is not object!");
        return DP_GET_SWITCH_INFO_FAIL;
    }
    cJSON* abilitiesJson = cJSON_GetObjectItemCaseSensitive(staticInfoJson, SWITCH_CALLERS.c_str());
    if (!cJSON_IsArray(abilitiesJson)) {
        HILOGE("abilitiesJson is not array!");
        return DP_GET_SWITCH_INFO_FAIL;
    }
    cJSON* abilityItem = NULL;
    cJSON_ArrayForEach(abilityItem, abilitiesJson) {
        if (!cJSON_IsObject(abilityItem)) {
            HILOGE("abilityItem is not object!");
            continue;
        }
        cJSON* abilityKeyItem = cJSON_GetObjectItemCaseSensitive(abilityItem, SWITCH_SERVICE_NAMES.c_str());
        if (!cJSON_IsString(abilityKeyItem) || abilityKeyItem->valuestring == NULL) {
            HILOGE("get abilityKeyItem fail!");
            continue;
        }
        cJSON* abilityValueItem = cJSON_GetObjectItemCaseSensitive(abilityItem, SWITCH_STATUS.c_str());
        if (!cJSON_IsString(abilityValueItem)) {
            HILOGE("get abilityValueItem fail!");
            continue;
        }
        std::string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
        std::string serviceId = abilityKeyItem->valuestring;
        std::string charKey = ProfileUtils::GenerateCharProfileKey(deviceId, serviceId, SWITCH_STATUS);
        std::string charValue = abilityValueItem->valuestring;
        if (charValue != SWITCH_ON && charValue != SWITCH_OFF) {
            HILOGE("switch status invaild");
            continue;
        }
        CharacteristicProfile characteristicProfile(deviceId, serviceId, SWITCH_STATUS, charValue);
        charProfileList.push_back(characteristicProfile);
    }
    return DP_SUCCESS;
}

void SwitchStatusCollector::AddSwitchStatusToDB(std::vector<CharacteristicProfile>& charProfileList)
{
    if (charProfileList.empty()) {
        return;
    }
    // get switch from db
    uint32_t switchFromDB;
    uint32_t switchLength;
    int32_t ret = SwitchProfileManager::GetInstance().GetLocalSwitchFromDB(switchFromDB, switchLength);
    if (ret == DP_SUCCESS && charProfileList.size() == switchLength) {
        return;
    }
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    std::map<std::string, CharacteristicProfile> oldProfileMap;
    for (const auto& [serviceName, pos] : SWITCH_SERVICE_MAP) {
        int32_t i = static_cast<int32_t>(pos);
        std::string itemSwitchValue = std::to_string((switchFromDB >> i) & NUM_1);
        const CharacteristicProfile oldSwitchProfile = {localUdid, serviceName, SWITCH_STATUS, itemSwitchValue};
        std::string charKey = ProfileUtils::GenerateCharProfileKey(localUdid, serviceName, SWITCH_STATUS);
        oldProfileMap[charKey] = oldSwitchProfile;
    }
    for (auto& profile : charProfileList) {
        std::string charKey = ProfileUtils::GenerateCharProfileKey(profile.GetDeviceId(), profile.GetServiceName(),
            profile.GetCharacteristicKey());
        auto iter = oldProfileMap.find(charKey);
        if (iter == oldProfileMap.end() || iter->second.GetCharacteristicValue() == profile.GetCharacteristicValue()) {
            continue;
        }
        profile.SetCharacteristicValue(iter->second.GetCharacteristicValue());
    }
    ret = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfileList);
    if (ret != DP_SUCCESS) {
        HILOGE("collect switch status error");
    }
}
} // namespace DeviceProfile
} // namespace OHOS