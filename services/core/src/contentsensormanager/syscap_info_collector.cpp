/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "syscap_info_collector.h"

#include "parameters.h"
#include "syscap_interface.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SyscapInfoCollector";
    const std::string SERVICE_ID = "syscap";
    const std::string SERVICE_TYPE = "syscap";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    constexpr int32_t MAX_DATALEN = 1128;
    constexpr int32_t INT_BYTES_LEN = 4;
}

bool SyscapInfoCollector::ConvertToProfile(DeviceProfile &profile)
{
    char osBuffer[PCID_MAIN_BYTES];
    if (!EncodeOsSyscap(osBuffer, PCID_MAIN_BYTES)) {
        HILOGE("EncodeOsSyscap failed");
        return false;
    }

    std::vector<int32_t> osSyscapData;
    for (int32_t i = 0; i < PCID_MAIN_BYTES/INT_BYTES_LEN; i++) {
        int32_t value = *((int32_t *)osBuffer + i);
        osSyscapData.push_back(value);
    }
    cJSON* jsonData = cJSON_CreateObject();
    if (!cJSON_IsObject(jsonData)) {
        HILOGE("Create cJSON failed!");
        cJSON_Delete(jsonData);
        return false;
    }
    if (!AddOsSyscapToJson(jsonData, osSyscapData)) {
        cJSON_Delete(jsonData);
        return false;
    }

    char* privateBuffer = nullptr;
    int32_t privateBufferLen;
    if (!EncodePrivateSyscap(&privateBuffer, &privateBufferLen)) {
        cJSON_Delete(jsonData);
        HILOGE("EncodePrivateSyscap failed");
        return false;
    }
    if (privateBufferLen + PCID_MAIN_BYTES > MAX_DATALEN) {
        free(privateBuffer);
        cJSON_Delete(jsonData);
        HILOGI("syscap data length too long");
        return false;
    }
    if (!AddPrivateSyscapToJson(jsonData, privateBuffer)) {
        free(privateBuffer);
        cJSON_Delete(jsonData);
        return false;
    }
    free(privateBuffer);
    std::string jsonStr;
    if (!GenJsonStr(jsonData, jsonStr)) {
        cJSON_Delete(jsonData);
        return false;
    }
    cJSON_Delete(jsonData);
    profile.SetOsSysCap(jsonStr);
    return true;
}

bool SyscapInfoCollector::AddOsSyscapToJson(cJSON* const jsonData, const std::vector<int32_t>& osSyscapData)
{
    cJSON* osSyscapJsonData = cJSON_CreateArray();
    if (!cJSON_IsArray(osSyscapJsonData)) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("Create JSON_ARRAY failed!");
        return false;
    }
    for (const auto& value : osSyscapData) {
        cJSON* jsonArrItem = cJSON_CreateNumber(value);
        if (jsonArrItem == NULL) {
            continue;
        }
        if (!cJSON_AddItemToArray(osSyscapJsonData, jsonArrItem)) {
            cJSON_Delete(jsonArrItem);
            continue;
        }
    }
    int32_t size = static_cast<int32_t>(osSyscapData.size());
    int32_t jsonArraySize = static_cast<int32_t>(cJSON_GetArraySize(osSyscapJsonData));
    if (jsonArraySize != size) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("size not equal!size=%{public}d, jsonArraySize=%{public}d", size, jsonArraySize);
        return false;
    }
    if (!cJSON_AddItemToObject(jsonData, CHARACTER_OS_SYSCAP.c_str(), osSyscapJsonData)) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("Add json array to Object failed!");
        return false;
    }
    return true;
}

bool SyscapInfoCollector::AddPrivateSyscapToJson(cJSON* const jsonData, const char* const privateBuffer)
{
    cJSON* item = cJSON_AddStringToObject(jsonData, CHARACTER_PRIVATE_SYSCAP.c_str(), privateBuffer);
    if (!cJSON_IsString(item)) {
        HILOGE("Add CHARACTER_PRIVATE_SYSCAP to cJSON failed!");
        return false;
    }
    return true;
}

bool SyscapInfoCollector::GenJsonStr(const cJSON* const jsonData, std::string& jsonStr)
{
    char* jsonChars = cJSON_PrintUnformatted(jsonData);
    if (jsonChars == NULL) {
        HILOGE("cJSON formatted to string failed!");
        return false;
    }
    jsonStr = jsonChars;
    cJSON_free(jsonChars);
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS