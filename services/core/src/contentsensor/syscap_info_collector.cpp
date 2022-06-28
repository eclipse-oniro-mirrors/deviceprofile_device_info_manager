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

#include "syscap_info_collector.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "nlohmann/json.hpp"
#include "parameters.h"
#include "syscap_interface.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
    const std::string TAG = "SyscapInfoCollector";

    const std::string SERVICE_ID = "syscap";
    const std::string SERVICE_TYPE = "syscap";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    constexpr int32_t MAX_DATALEN = 1128;
    constexpr int32_t INT_BYTES_LEN = 4;
}

bool SyscapInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);

    char osBuffer[PCID_MAIN_BYTES];
    if (!EncodeOsSyscap(osBuffer, PCID_MAIN_BYTES)) {
        HILOGE("EncodeOsSyscap failed");
        return false;
    }

    std::vector<int32_t> osSyscapData;
    for (int i = 0; i < PCID_MAIN_BYTES/INT_BYTES_LEN; i++) {
        int32_t value = *((int32_t *)osBuffer + i);
        osSyscapData.push_back(value);
    }

    nlohmann::json jsonData;
    nlohmann::json osSyscapJsonData(osSyscapData);
    jsonData[CHARACTER_OS_SYSCAP] = osSyscapJsonData;

    char* privateBuffer = nullptr;
    int32_t privateBufferLen;
    if (!EncodePrivateSyscap(&privateBuffer, &privateBufferLen)) {
        HILOGE("EncodePrivateSyscap failed");
        return false;
    }
    if (privateBufferLen + PCID_MAIN_BYTES > MAX_DATALEN) {
        free(privateBuffer);
        HILOGI("syscap data length too long");
        return false;
    }
    jsonData[CHARACTER_PRIVATE_SYSCAP] = privateBuffer;
    free(privateBuffer);
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS