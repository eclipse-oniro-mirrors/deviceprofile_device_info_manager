/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "macro_utils.h"
#include "distributed_device_profile_constants.h"
#include "nlohmann/json.hpp"
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
    nlohmann::json json;
    json[DEVICE_ID] = ProfileUtils::GetAnonyString(deviceId_);
    json[DEVICE_ID_TYPE] = deviceIdType_;
    json[DEVICE_ID_HASH] = deviceIdHash_;
    json[STATUS] = status_;
    return json.dump();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS