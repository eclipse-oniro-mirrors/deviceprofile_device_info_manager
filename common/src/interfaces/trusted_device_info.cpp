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

#include "trusted_device_info.h"

#include "cJSON.h"

#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "TrustedDeviceInfo";
    const std::string NETWORK_ID = "networkId";
    const std::string AUTH_FORM = "authForm";
    const std::string UDID = "uuid";
    const std::string UUID = "udid";
}

std::string TrustedDeviceInfo::GetNetworkId() const
{
    return networkId_;
}

void TrustedDeviceInfo::SetNetworkId(const std::string& networkId)
{
    networkId_ = networkId;
}

int32_t TrustedDeviceInfo::GetAuthForm() const
{
    return authForm_;
}

void TrustedDeviceInfo::SetAuthForm(int32_t authForm)
{
    authForm_ = authForm;
}

uint16_t TrustedDeviceInfo::GetDeviceTypeId() const
{
    return deviceTypeId_;
}

void TrustedDeviceInfo::SetDeviceTypeId(uint16_t deviceTypeId)
{
    deviceTypeId_ = deviceTypeId;
}

std::string TrustedDeviceInfo::GetOsVersion() const
{
    return osVersion_;
}

void TrustedDeviceInfo::SetOsVersion(const std::string& osVersion)
{
    osVersion_ = osVersion;
}

int32_t TrustedDeviceInfo::GetOsType() const
{
    return osType_;
}

void TrustedDeviceInfo::SetOsType(int32_t osType)
{
    osType_ = osType;
}

std::string TrustedDeviceInfo::GetUdid() const
{
    return udid_;
}

void TrustedDeviceInfo::SetUdid(const std::string& udid)
{
    udid_ = udid;
}

std::string TrustedDeviceInfo::GetUuid() const
{
    return uuid_;
}

void TrustedDeviceInfo::SetUuid(const std::string& uuid)
{
    uuid_ = uuid;
}

bool TrustedDeviceInfo::operator!=(const TrustedDeviceInfo& other) const
{
    return (networkId_ != other.GetNetworkId() || authForm_ != other.GetAuthForm() ||
        deviceTypeId_ != other.GetDeviceTypeId() || osVersion_ != other.GetOsVersion() ||
        osType_ != other.GetOsType() || udid_ != other.GetUdid() ||
        uuid_ != other.GetUuid());
}

bool TrustedDeviceInfo::operator<(const TrustedDeviceInfo& other) const
{
    return ((networkId_ < other.GetNetworkId()) ||
        (networkId_ == other.GetNetworkId() && authForm_ < other.GetAuthForm()) ||
        (networkId_ == other.GetNetworkId() && authForm_ == other.GetAuthForm() &&
            deviceTypeId_ < other.GetDeviceTypeId()) ||
        (networkId_ == other.GetNetworkId() && authForm_ == other.GetAuthForm() &&
            deviceTypeId_ == other.GetDeviceTypeId() && osVersion_ < other.GetOsVersion()) ||
        (networkId_ == other.GetNetworkId() && authForm_ == other.GetAuthForm() &&
            deviceTypeId_ == other.GetDeviceTypeId() && osVersion_ == other.GetOsVersion() &&
            osType_ < other.GetOsType()) ||
        (networkId_ == other.GetNetworkId() && authForm_ == other.GetAuthForm() &&
            deviceTypeId_ == other.GetDeviceTypeId() && osVersion_ == other.GetOsVersion() &&
            osType_ == other.GetOsType() && udid_ < other.GetUdid()) ||
        (networkId_ == other.GetNetworkId() && authForm_ == other.GetAuthForm() &&
            deviceTypeId_ == other.GetDeviceTypeId() && osVersion_ == other.GetOsVersion() &&
            osType_ == other.GetOsType() && udid_ == other.GetUdid() && uuid_ < other.GetUuid()));
}

bool TrustedDeviceInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, networkId_, false);
    WRITE_HELPER_RET(parcel, Int32, authForm_, false);
    WRITE_HELPER_RET(parcel, Uint16, deviceTypeId_, false);
    WRITE_HELPER_RET(parcel, String, osVersion_, false);
    WRITE_HELPER_RET(parcel, Int32, osType_, false);
    WRITE_HELPER_RET(parcel, String, udid_, false);
    WRITE_HELPER_RET(parcel, String, uuid_, false);
    return true;
}

bool TrustedDeviceInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, networkId_, false);
    READ_HELPER_RET(parcel, Int32, authForm_, false);
    READ_HELPER_RET(parcel, Uint16, deviceTypeId_, false);
    READ_HELPER_RET(parcel, String, osVersion_, false);
    READ_HELPER_RET(parcel, Int32, osType_, false);
    READ_HELPER_RET(parcel, String, udid_, false);
    READ_HELPER_RET(parcel, String, uuid_, false);
    return true;
}

std::string TrustedDeviceInfo::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, NETWORK_ID.c_str(), ProfileUtils::GetAnonyString(networkId_).c_str());
    cJSON_AddNumberToObject(json, AUTH_FORM.c_str(), authForm_);
    cJSON_AddNumberToObject(json, DEVICE_TYPE_ID.c_str(), deviceTypeId_);
    cJSON_AddStringToObject(json, OS_VERSION.c_str(), ProfileUtils::GetAnonyString(osVersion_).c_str());
    cJSON_AddNumberToObject(json, OS_TYPE.c_str(), osType_);
    cJSON_AddStringToObject(json, UDID.c_str(), ProfileUtils::GetAnonyString(udid_).c_str());
    cJSON_AddStringToObject(json, UUID.c_str(), ProfileUtils::GetAnonyString(uuid_).c_str());
    char* jsonChars = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (jsonChars == NULL) {
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS