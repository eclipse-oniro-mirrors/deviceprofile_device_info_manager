/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "device_profile_utils.h"

#include <list>
#include <string>

#include "parcel.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DeviceProfileUtils";

constexpr int32_t NON_ANONYMIZED_LENGTH = 6;
constexpr uint32_t MAX_EVENT_LEN = 1000000;
const std::string EMPTY_DEVICE_ID = "";
}

bool DeviceProfileUtils::WriteProfileEvents(const std::list<ProfileEvent>& profileEvents, Parcel& parcel)
{
    size_t size = profileEvents.size();
    PARCEL_WRITE_HELPER_RET(parcel, Uint32, static_cast<uint32_t>(size), false);
    for (auto profileEvent : profileEvents) {
        PARCEL_WRITE_HELPER_RET(parcel, Uint32, static_cast<uint32_t>(profileEvent), false);
    }
    return true;
}

bool DeviceProfileUtils::ReadProfileEvents(Parcel& parcel, std::list<ProfileEvent>& profileEvents)
{
    uint32_t numEvents = parcel.ReadUint32();
    if (numEvents > MAX_EVENT_LEN) {
        return false;
    }

    for (uint32_t i = 0; i < numEvents; i++) {
        ProfileEvent profileEvent = static_cast<ProfileEvent>(parcel.ReadUint32());
        if (profileEvent >= EVENT_PROFILE_END || profileEvent == EVENT_UNKNOWN) {
            return false;
        }
        profileEvents.emplace_back(profileEvent);
    }
    return true;
}

std::string DeviceProfileUtils::AnonymizeDeviceId(const std::string& deviceId)
{
    if (deviceId.length() < NON_ANONYMIZED_LENGTH) {
        return EMPTY_DEVICE_ID;
    }
    std::string anonDeviceId = deviceId.substr(0, NON_ANONYMIZED_LENGTH);
    anonDeviceId.append("******");
    return anonDeviceId;
}

std::string DeviceProfileUtils::AnonymizeString(const std::string& value)
{
    constexpr size_t INT32_SHORT_ID_LENGTH = 20;
    constexpr size_t INT32_PLAINTEXT_LENGTH = 4;
    constexpr size_t INT32_MIN_ID_LENGTH = 3;
    std::string res;
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LENGTH) {
        return tmpStr;
    }

    if (strLen <= INT32_SHORT_ID_LENGTH) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAINTEXT_LENGTH);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAINTEXT_LENGTH, INT32_PLAINTEXT_LENGTH);
    }
    return res;
}
} // namespace DeviceProfile
} // namespace OHOS
