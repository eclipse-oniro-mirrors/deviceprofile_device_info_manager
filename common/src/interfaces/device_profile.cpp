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

#include "device_profile.h"
#include "cJSON.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DeviceProfile";
}
std::string DeviceProfile::GetDeviceId() const
{
    return deviceId_;
}

void DeviceProfile::SetDeviceId(const std::string& deviceId)
{
    deviceId_ = deviceId;
}

std::string DeviceProfile::GetDeviceTypeName() const
{
    return deviceTypeName_;
}

void DeviceProfile::SetDeviceTypeName(const std::string &deviceTypeName)
{
    deviceTypeName_ = deviceTypeName;
}

int32_t DeviceProfile::GetDeviceTypeId() const
{
    return deviceTypeId_;
}

void DeviceProfile::SetDeviceTypeId(int32_t deviceTypeId)
{
    deviceTypeId_ = deviceTypeId;
}

std::string DeviceProfile::GetDeviceName() const
{
    return deviceName_;
}

void DeviceProfile::SetDeviceName(const std::string& deviceName)
{
    deviceName_ = deviceName;
}

std::string DeviceProfile::GetManufactureName() const
{
    return manufactureName_;
}

void DeviceProfile::SetManufactureName(std::string manufactureName)
{
    manufactureName_ = manufactureName;
}

std::string DeviceProfile::GetDeviceModel() const
{
    return deviceModel_;
}

void DeviceProfile::SetDeviceModel(const std::string &deviceModel)
{
    deviceModel_ = deviceModel;
}

int64_t DeviceProfile::GetStorageCapability() const
{
    return storageCapability_;
}

void DeviceProfile::SetStorageCapability(int64_t storageCapability)
{
    storageCapability_ = storageCapability;
}

int32_t DeviceProfile::GetOsApiLevel() const
{
    return osApiLevel_;
}

void DeviceProfile::SetOsApiLevel(int32_t osApiLevel)
{
    osApiLevel_ = osApiLevel;
}

std::string DeviceProfile::GetOsVersion() const
{
    return osVersion_;
}

void DeviceProfile::SetOsVersion(const std::string& osVersion)
{
    osVersion_ = osVersion;
}

int32_t DeviceProfile::GetOsType() const
{
    return osType_;
}

void DeviceProfile::SetOsType(int32_t osType)
{
    osType_ = osType;
}

std::string DeviceProfile::GetOsSysCap() const
{
    return osSysCap_;
}

void DeviceProfile::SetOsSysCap(const std::string& osSysCap)
{
    osSysCap_ = osSysCap;
}

bool DeviceProfile::GetIsMuitUser() const
{
    return isMuitUser_;
}

void DeviceProfile::SetIsMuitUser(bool isMuitUser)
{
    isMuitUser_ = isMuitUser;
}

int32_t DeviceProfile::GetUserId() const
{
    return userId_;
}

void DeviceProfile::SetUserId(int32_t userId)
{
    userId_ = userId;
}

bool DeviceProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, deviceTypeName_, false);
    WRITE_HELPER_RET(parcel, Int32, deviceTypeId_, false);
    WRITE_HELPER_RET(parcel, String, deviceName_, false);
    WRITE_HELPER_RET(parcel, String, manufactureName_, false);
    WRITE_HELPER_RET(parcel, String, deviceModel_, false);
    WRITE_HELPER_RET(parcel, Int64, storageCapability_, false);
    WRITE_HELPER_RET(parcel, String, osSysCap_, false);
    WRITE_HELPER_RET(parcel, Int32, osApiLevel_, false);
    WRITE_HELPER_RET(parcel, String, osVersion_, false);
    WRITE_HELPER_RET(parcel, Int32, osType_, false);
    WRITE_HELPER_RET(parcel, Bool, isMuitUser_, false);
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    return true;
}

bool DeviceProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, String, deviceTypeName_, false);
    READ_HELPER_RET(parcel, Int32, deviceTypeId_, false);
    READ_HELPER_RET(parcel, String, deviceName_, false);
    READ_HELPER_RET(parcel, String, manufactureName_, false);
    READ_HELPER_RET(parcel, String, deviceModel_, false);
    READ_HELPER_RET(parcel, Int64, storageCapability_, false);
    READ_HELPER_RET(parcel, String, osSysCap_, false);
    READ_HELPER_RET(parcel, Int32, osApiLevel_, false);
    READ_HELPER_RET(parcel, String, osVersion_, false);
    READ_HELPER_RET(parcel, Int32, osType_, false);
    READ_HELPER_RET(parcel, Bool, isMuitUser_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    return true;
}

bool DeviceProfile::operator!=(const DeviceProfile& deviceProfile) const
{
    bool isNotEqual = (deviceId_ != deviceProfile.GetDeviceId() || deviceTypeName_ != deviceProfile.GetDeviceTypeName()
        || deviceTypeId_ != deviceProfile.GetDeviceTypeId() || deviceName_ != deviceProfile.GetDeviceName() ||
        manufactureName_ != deviceProfile.GetManufactureName() || deviceModel_ != deviceProfile.GetDeviceModel() ||
        storageCapability_ != deviceProfile.GetStorageCapability() || osSysCap_ != deviceProfile.GetOsSysCap() ||
        osApiLevel_ != deviceProfile.GetOsApiLevel() || osVersion_ != deviceProfile.GetOsVersion() || osType_ !=
        deviceProfile.GetOsType() || isMuitUser_ != deviceProfile.GetIsMuitUser() || userId_ !=
        deviceProfile.GetUserId());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string DeviceProfile::dump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(deviceId_).c_str());
    cJSON_AddStringToObject(json, DEVICE_TYPE_NAME.c_str(), deviceTypeName_.c_str());
    cJSON_AddNumberToObject(json, DEVICE_TYPE_ID.c_str(), deviceTypeId_);
    cJSON_AddStringToObject(json, DEVICE_NAME.c_str(), deviceName_.c_str());
    cJSON_AddStringToObject(json, MANUFACTURE_NAME.c_str(), manufactureName_.c_str());
    cJSON_AddStringToObject(json, DEVICE_MODEL.c_str(), deviceModel_.c_str());
    cJSON_AddNumberToObject(json, STORAGE_CAPACITY.c_str(), storageCapability_);
    cJSON_AddStringToObject(json, OS_SYS_CAPACITY.c_str(), osSysCap_.c_str());
    cJSON_AddNumberToObject(json, OS_API_LEVEL.c_str(), osApiLevel_);
    cJSON_AddStringToObject(json, OS_VERSION.c_str(), osVersion_.c_str());
    cJSON_AddNumberToObject(json, OS_TYPE.c_str(), osType_);
    cJSON_AddBoolToObject(json, IS_MULTI_USER.c_str(), isMuitUser_);
    cJSON_AddNumberToObject(json, USER_ID.c_str(), userId_);
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    cJSON_free(jsonChars);
    return jsonStr;
}

std::string DeviceProfile::AnnoymizeDump() const
{
    cJSON* json = cJSON_CreateObject();
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        return EMPTY_STRING;
    }
    cJSON_AddStringToObject(json, DEVICE_ID.c_str(), ProfileUtils::GetAnonyString(deviceId_).c_str());
    cJSON_AddStringToObject(json, DEVICE_TYPE_NAME.c_str(), deviceTypeName_.c_str());
    cJSON_AddNumberToObject(json, DEVICE_TYPE_ID.c_str(), deviceTypeId_);
    cJSON_AddStringToObject(json, DEVICE_NAME.c_str(), deviceName_.c_str());
    cJSON_AddStringToObject(json, MANUFACTURE_NAME.c_str(), manufactureName_.c_str());
    cJSON_AddStringToObject(json, DEVICE_MODEL.c_str(), deviceModel_.c_str());
    cJSON_AddStringToObject(json, STORAGE_CAPACITY.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(storageCapability_)).c_str());
    cJSON_AddStringToObject(json, OS_SYS_CAPACITY.c_str(),
        ProfileUtils::GetAnonyString(osSysCap_).c_str());
    cJSON_AddStringToObject(json, OS_API_LEVEL.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(osApiLevel_)).c_str());
    cJSON_AddStringToObject(json, OS_VERSION.c_str(),
        ProfileUtils::GetAnonyString(osVersion_).c_str());
    cJSON_AddStringToObject(json, OS_TYPE.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(osType_)).c_str());
    cJSON_AddBoolToObject(json, IS_MULTI_USER.c_str(), isMuitUser_);
    cJSON_AddStringToObject(json, USER_ID.c_str(),
        ProfileUtils::GetAnonyString(std::to_string(userId_)).c_str());
    char* jsonChars = cJSON_PrintUnformatted(json);
    if (jsonChars == NULL) {
        cJSON_Delete(json);
        HILOGE("cJSON formatted to string failed!");
        return EMPTY_STRING;
    }
    std::string jsonStr = jsonChars;
    cJSON_Delete(json);
    cJSON_free(jsonChars);
    return jsonStr;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
