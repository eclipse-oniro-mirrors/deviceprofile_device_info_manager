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

#include "device_profile.h"
#include "macro_utils.h"
#include "distributed_device_profile_constants.h"
#include "nlohmann/json.hpp"
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

bool DeviceProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, deviceTypeName_, false);
    WRITE_HELPER_RET(parcel, Int32, deviceTypeId_, false);
    WRITE_HELPER_RET(parcel, String, deviceName_, false);
    WRITE_HELPER_RET(parcel, String, manufactureName_, false);
    WRITE_HELPER_RET(parcel, String, deviceModel_, false);
    WRITE_HELPER_RET(parcel, String, serialNumberId_, false);
    WRITE_HELPER_RET(parcel, Int64, storageCapability_, false);
    WRITE_HELPER_RET(parcel, String, osSysCap_, false);
    WRITE_HELPER_RET(parcel, Int32, osApiLevel_, false);
    WRITE_HELPER_RET(parcel, String, osVersion_, false);
    WRITE_HELPER_RET(parcel, Int32, osType_, false);
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
    READ_HELPER_RET(parcel, String, serialNumberId_, false);
    READ_HELPER_RET(parcel, Int64, storageCapability_, false);
    READ_HELPER_RET(parcel, String, osSysCap_, false);
    READ_HELPER_RET(parcel, Int32, osApiLevel_, false);
    READ_HELPER_RET(parcel, String, osVersion_, false);
    READ_HELPER_RET(parcel, Int32, osType_, false);
    return true;
}

bool DeviceProfile::operator!=(const DeviceProfile& deviceProfile) const
{
    bool isNotEqual = (deviceId_ != deviceProfile.GetDeviceId() || deviceTypeName_ != deviceProfile.GetDeviceTypeName()
        || deviceTypeId_ != deviceProfile.GetDeviceTypeId() || deviceName_ != deviceProfile.GetDeviceName() ||
        manufactureName_ != deviceProfile.GetManufactureName() || deviceModel_ != deviceProfile.GetDeviceModel() ||
        serialNumberId_ != deviceProfile.GetSerialNumberId() || storageCapability_ !=
        deviceProfile.GetStorageCapability() || osSysCap_ != deviceProfile.GetOsSysCap() || osApiLevel_ !=
        deviceProfile.GetOsApiLevel() || osVersion_ != deviceProfile.GetOsVersion() || osType_ !=
        deviceProfile.GetOsType());
    if (isNotEqual) {
        return true;
    } else {
        return false;
    }
}

std::string DeviceProfile::dump() const
{
    nlohmann::json json;
    json[DEVICE_ID] = ProfileUtils::GetAnonyString(deviceId_);
    json[DEVICE_TYPE_NAME] = deviceTypeName_;
    json[DEVICE_TYPE_ID] = deviceTypeId_;
    json[DEVICE_NAME] = deviceName_;
    json[MANUFACTURE_NAME] = manufactureName_;
    json[DEVICE_MODEL] = deviceModel_;
    json[SERIAL_NUMBER_ID] = serialNumberId_;
    json[STORAGE_CAPACITY] = storageCapability_;
    json[OS_SYS_CAPACITY] = osSysCap_;
    json[OS_API_LEVEL] = osApiLevel_;
    json[OS_VERSION] = osVersion_;
    json[OS_TYPE] = osType_;
    return json.dump();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS