/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "characteristic_profile.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "CharacteristicProfile";
}
std::string  CharacteristicProfile::GetDeviceId() const
{
    return deviceId_;
}

void CharacteristicProfile::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

std::string  CharacteristicProfile::GetServiceName() const
{
    return serviceName_;
}

void CharacteristicProfile::SetServiceName(const std::string& serviceName)
{
    serviceName_ = serviceName;
}

std::string  CharacteristicProfile::GetCharacteristicKey() const
{
    return characteristicKey_;
}

void CharacteristicProfile::SetCharacteristicKey(const std::string& characteristicId)
{
    characteristicKey_ = characteristicId;
}

std::string  CharacteristicProfile::GetCharacteristicValue() const
{
    return characteristicValue_;
}

void CharacteristicProfile::SetCharacteristicValue(const std::string& characteristicValue)
{
    characteristicValue_ = characteristicValue;
}

bool CharacteristicProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, serviceName_, false);
    WRITE_HELPER_RET(parcel, String, characteristicKey_, false);
    WRITE_HELPER_RET(parcel, String, characteristicValue_, false);
    return true;
}

bool CharacteristicProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, String, serviceName_, false);
    READ_HELPER_RET(parcel, String, characteristicKey_, false);
    READ_HELPER_RET(parcel, String, characteristicValue_, false);
    return true;
}

bool CharacteristicProfile::operator!=(const CharacteristicProfile& charProfile) const
{
    bool isNotEqual = (deviceId_ != charProfile.GetDeviceId() || serviceName_ != charProfile.GetServiceName() ||
        characteristicKey_ != charProfile.GetCharacteristicKey() ||
        characteristicValue_ != charProfile.GetCharacteristicValue());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string CharacteristicProfile::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(deviceId_).c_str());
    cJSON_AddStringToObject(json, SERVICE_NAME.c_str(), serviceName_.c_str());
    cJSON_AddStringToObject(json, CHARACTERISTIC_KEY.c_str(), characteristicKey_.c_str());
    cJSON_AddStringToObject(json, CHARACTERISTIC_VALUE.c_str(), characteristicValue_.c_str());
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS