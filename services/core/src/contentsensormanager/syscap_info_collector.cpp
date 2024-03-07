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
    cJSON* jsonData = cJSON_CreateObject();
    if(!cJSON_IsObject(jsonData)) {
        cJSON_Delete(jsonData);
        HILOGE("Create cJSON failed!");
        return false;
    }
    if(!GetOsSyscap(jsonData)) {
        cJSON_Delete(jsonData);
        HILOGE("GetOsSyscap failed");
        return false;
    }

    char* privateBuffer = nullptr;
    int32_t privateBufferLen;
    if (!EncodePrivateSyscap(&privateBuffer, &privateBufferLen)) {
        HILOGE("EncodePrivateSyscap failed");
        cJSON_Delete(jsonData);
        return false;
    }
    if (privateBufferLen + PCID_MAIN_BYTES > MAX_DATALEN) {
        free(privateBuffer);
        HILOGI("syscap data length too long");
        cJSON_Delete(jsonData);
        return false;
    }
    cJSON* item = cJSON_AddStringToObject(jsonData, CHARACTER_PRIVATE_SYSCAP.c_str(), privateBuffer);
    if(!cJSON_IsString(item)) {
        free(privateBuffer);
        HILOGE("Add CHARACTER_PRIVATE_SYSCAP to cJSON failed!");
        cJSON_Delete(jsonData);
        return false;
    }
    free(privateBuffer);
    char* jsonChars = cJSON_PrintUnformatted(jsonData);
    if (jsonChars == NULL) {
        cJSON_Delete(jsonData);
        HILOGE("cJSON formatted to string failed!");
        return false;
    }
    std::string jsonStr = jsonChars;
    profile.SetOsSysCap(jsonStr);
    cJSON_Delete(jsonData);
    free(jsonChars);
    return true;
}

bool SyscapInfoCollector::GetOsSyscap(cJSON* jsonData) {
    char osBuffer[PCID_MAIN_BYTES];
    if (!EncodeOsSyscap(osBuffer, PCID_MAIN_BYTES)) {
        HILOGE("EncodeOsSyscap failed");
        return false;
    }
    cJSON* osSyscapJsonData = cJSON_CreateArray();
    if(!cJSON_IsArray(osSyscapJsonData)) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("Create JSON_ARRAY failed!");
        return false;
    }
    int32_t size = PCID_MAIN_BYTES/INT_BYTES_LEN;
    for (int32_t i = 0; i < size; i++) {
        int32_t value = *((int32_t *)osBuffer + i);
        cJSON_AddItemToArray(osSyscapJsonData, cJSON_CreateNumber(value));
    }
    int32_t jsonArraySize = static_cast<int32_t>(cJSON_GetArraySize(osSyscapJsonData)); 
    if(jsonArraySize != size) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("size not equal!size=%{public}d, jsonArraySize=%{public}d", size, jsonArraySize);
        return false;
    }
    if(!cJSON_AddItemToObject(jsonData, CHARACTER_OS_SYSCAP.c_str(), osSyscapJsonData)) {
        cJSON_Delete(osSyscapJsonData);
        HILOGE("Add json array to Object failed!");
        return false;
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS