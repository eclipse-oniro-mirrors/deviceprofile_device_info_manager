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

#include "characteristic_profile_filter_option.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "ipc_utils.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "CharacteristicProfile";
}
std::string CharacteristicProfileFilterOption::GetAccountld() const
{
    return accountld_;
}

void CharacteristicProfileFilterOption::SetAccountld(const std::string& accountld)
{
    accountld_ = accountld;
}

std::string CharacteristicProfileFilterOption::GetServiceId() const
{
    return serviceId_;
}

void CharacteristicProfileFilterOption::SetServiceId(const std::string& serviceId)
{
    serviceId_ = serviceId;
}

std::string CharacteristicProfileFilterOption::GetWiseDeviceId() const
{
    return wiseDeviceId_;
}

void CharacteristicProfileFilterOption::SetWiseDeviceId(const std::string& wiseDeviceId)
{
    wiseDeviceId_ = wiseDeviceId;
}

int32_t CharacteristicProfileFilterOption::GetUserId() const
{
    return userId_;
}

void CharacteristicProfileFilterOption::SetUserId(int32_t userId)
{
    userId_ = userId;
}

std::vector<int32_t> CharacteristicProfileFilterOption::GetCharacteristicProfileIds() const
{
    return characteristicProfileIds_;
}

void CharacteristicProfileFilterOption::SetCharacteristicProfileIds(std::vector<int32_t>& characteristicProfileIds)
{
    characteristicProfileIds_ = characteristicProfileIds;
}

std::string CharacteristicProfileFilterOption::GetCharacteristicKey() const
{
    return characteristicKey_;
}

void CharacteristicProfileFilterOption::SetCharacteristicKey(std::string& characteristicKey)
{
    characteristicKey_ = characteristicKey;
}

std::string CharacteristicProfileFilterOption::GetDeviceId() const
{
    return deviceId_;
}

void CharacteristicProfileFilterOption::SetDeviceId(std::string& deviceId)
{
    deviceId_ = deviceId;
}

int32_t CharacteristicProfileFilterOption::GetServiceProfileId() const
{
    return serviceProfileId_;
}

void CharacteristicProfileFilterOption::SetServiceProfileId(int32_t serviceProfileId)
{
    serviceProfileId_ = serviceProfileId;
}

bool CharacteristicProfileFilterOption::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, accountld_, false);
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, wiseDeviceId_, false);
    WRITE_HELPER_RET(parcel, String, serviceId_, false);
    WRITE_HELPER_RET(parcel, String, characteristicKey_, false);
    WRITE_HELPER_RET(parcel, Int32, serviceProfileId_, false);
    if (!IpcUtils::Marshalling(parcel, characteristicProfileIds_)) {
        HILOGE("read parcel fail!");
        return false;
    }
    return true;
}

bool CharacteristicProfileFilterOption::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, accountld_, false);
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, String, wiseDeviceId_, false);
    READ_HELPER_RET(parcel, String, serviceId_, false);
    READ_HELPER_RET(parcel, String, characteristicKey_, false);
    READ_HELPER_RET(parcel, Int32, serviceProfileId_, false);
    if (!IpcUtils::UnMarshalling(parcel, characteristicProfileIds_)) {
        HILOGE("read parcel fail!");
        return false;
    }
    return true;
}

std::string CharacteristicProfileFilterOption::dump() const
{
    return "";
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
