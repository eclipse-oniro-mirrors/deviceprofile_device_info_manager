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

#include "trust_device_profile.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "TrustDeviceProfile";
}
std::string TrustDeviceProfile::GetDeviceId() const
{
    return deviceId_;
}

void TrustDeviceProfile::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

int32_t TrustDeviceProfile::GetDeviceIdType() const
{
    return deviceIdType_;
}

void TrustDeviceProfile::SetDeviceIdType(int32_t deviceType)
{
    deviceIdType_ = deviceType;
}

std::string TrustDeviceProfile::GetDeviceIdHash() const
{
    return deviceIdHash_;
}

void TrustDeviceProfile::SetDeviceIdHash(const std::string& deviceIdHash)
{
    deviceIdHash_ = deviceIdHash;
}

int32_t TrustDeviceProfile::GetStatus() const
{
    return status_;
}

void TrustDeviceProfile::SetStatus(int32_t status)
{
    status_ = status;
}

uint32_t TrustDeviceProfile::GetBindType() const
{
    return bindType_;
}

void TrustDeviceProfile::SetBindType(uint32_t bindType)
{
    bindType_ = bindType;
}

bool TrustDeviceProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, Uint32, deviceIdType_, false);
    WRITE_HELPER_RET(parcel, String, deviceIdHash_, false);
    WRITE_HELPER_RET(parcel, Int32, status_, false);
    return true;
}

bool TrustDeviceProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, Uint32, deviceIdType_, false);
    READ_HELPER_RET(parcel, String, deviceIdHash_, false);
    READ_HELPER_RET(parcel, Int32, status_, false);
    return true;
}

std::string TrustDeviceProfile::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(deviceId_).c_str());
    cJSON_AddNumberToObject(json, DEVICE_ID_TYPE.c_str(), deviceIdType_);
    cJSON_AddStringToObject(json, DEVICE_ID_HASH.c_str(), deviceIdHash_.c_str());
    cJSON_AddNumberToObject(json, STATUS.c_str(), status_);
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