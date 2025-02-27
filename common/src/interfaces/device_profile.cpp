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

void DeviceProfile::SetDeviceModel(const std::string& deviceModel)
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

bool DeviceProfile::IsMultiUser() const
{
    return isMultiUser_;
}

void DeviceProfile::SetIsMultiUser(bool isMultiUser)
{
    isMultiUser_ = isMultiUser;
}

int32_t DeviceProfile::GetUserId() const
{
    return userId_;
}

void DeviceProfile::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t DeviceProfile::GetId() const
{
    return id_;
}

void DeviceProfile::SetId(int32_t id)
{
    id_ = id;
}

std::string DeviceProfile::GetDevType() const
{
    return devType_;
}

void DeviceProfile::SetDevType(const std::string& devType)
{
    devType_ = devType;
}

std::string DeviceProfile::GetManu() const
{
    return manu_;
}

void DeviceProfile::SetManu(const std::string& manu)
{
    manu_ = manu;
}

std::string DeviceProfile::GetSn() const
{
    return sn_;
}

void DeviceProfile::SetSn(const std::string& sn)
{
    sn_ = sn;
}

std::string DeviceProfile::GetProductId() const
{
    return productId_;
}

void DeviceProfile::SetProductId(const std::string& productId)
{
    productId_ = productId;
}

std::string DeviceProfile::GetSubProductId() const
{
    return subProductId_;
}

void DeviceProfile::SetSubProductId(const std::string& subProductId)
{
    subProductId_ = subProductId;
}

std::string DeviceProfile::GetHiv() const
{
    return hiv_;
}

void DeviceProfile::SetHiv(const std::string& hiv)
{
    hiv_ = hiv;
}

std::string DeviceProfile::GetMac() const
{
    return mac_;
}

void DeviceProfile::SetMac(const std::string& mac)
{
    mac_ = mac;
}

std::string DeviceProfile::GetFwv() const
{
    return fwv_;
}

void DeviceProfile::SetFwv(const std::string& fwv)
{
    fwv_ = fwv;
}

std::string DeviceProfile::GetHwv() const
{
    return hwv_;
}

void DeviceProfile::SetHwv(const std::string& hwv)
{
    hwv_ = hwv;
}

std::string DeviceProfile::GetSwv() const
{
    return swv_;
}

void DeviceProfile::SetSwv(const std::string& swv)
{
    swv_ = swv;
}

int32_t DeviceProfile::GetProtType() const
{
    return protType_;
}

void DeviceProfile::SetProtType(int32_t protType)
{
    protType_ = protType;
}

std::string DeviceProfile::GetWiseUserId() const
{
    return wiseUserId_;
}

void DeviceProfile::SetWiseUserId(const std::string& wiseUserId)
{
    wiseUserId_ = wiseUserId;
}

std::string DeviceProfile::GetWiseDeviceId() const
{
    return wiseDeviceId_;
}

void DeviceProfile::SetWiseDeviceId(const std::string& wiseDeviceId)
{
    wiseDeviceId_ = wiseDeviceId;
}

std::string DeviceProfile::GetRegisterTime() const
{
    return registerTime_;
}

void DeviceProfile::SetRegisterTime(const std::string& registerTime)
{
    registerTime_ = registerTime;
}

std::string DeviceProfile::GetModifyTime() const
{
    return modifyTime_;
}

void DeviceProfile::SetModifyTime(std::string modifyTime)
{
    modifyTime_ = modifyTime;
}

std::string DeviceProfile::GetShareTime() const
{
    return shareTime_;
}

void DeviceProfile::SetShareTime(const std::string& shareTime)
{
    shareTime_ = shareTime;
}

std::string DeviceProfile::GetAccountId() const
{
    return accountId_;
}

void DeviceProfile::SetAccountId(const std::string& accountId)
{
    accountId_ = accountId;
}

const std::string DeviceProfile::GetBleMac() const
{
    return bleMac_;
}

void DeviceProfile::SetBleMac(const std::string& bleMac)
{
    bleMac_ = bleMac;
}

const std::string DeviceProfile::GetBrMac() const
{
    return brMac_;
}

void DeviceProfile::SetBrMac(const std::string& brMac)
{
    brMac_ = brMac;
}

const std::string DeviceProfile::GetSleMac() const
{
    return sleMac_;
}

void DeviceProfile::SetSleMac(const std::string& sleMac)
{
    sleMac_ = sleMac;
}

int32_t DeviceProfile::GetSetupType() const
{
    return setupType_;
}

void DeviceProfile::SetSetupType(int32_t setupType)
{
    setupType_ = setupType;
}

std::string DeviceProfile::GetInnerModel() const
{
    return innerModel_;
}

void DeviceProfile::SetInnerModel(const std::string& innerModel)
{
    innerModel_ = innerModel;
}

bool DeviceProfile::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER_RET(parcel, String, deviceId_, false);
    WRITE_HELPER_RET(parcel, String, deviceName_, false);
    WRITE_HELPER_RET(parcel, String, manufactureName_, false);
    WRITE_HELPER_RET(parcel, String, deviceModel_, false);
    WRITE_HELPER_RET(parcel, Int64, storageCapability_, false);
    WRITE_HELPER_RET(parcel, String, osSysCap_, false);
    WRITE_HELPER_RET(parcel, Int32, osApiLevel_, false);
    WRITE_HELPER_RET(parcel, String, osVersion_, false);
    WRITE_HELPER_RET(parcel, Int32, osType_, false);
    WRITE_HELPER_RET(parcel, Bool, isMultiUser_, false);
    WRITE_HELPER_RET(parcel, Int32, userId_, false);
    WRITE_HELPER_RET(parcel, String, devType_, false);
    WRITE_HELPER_RET(parcel, String, manu_, false);
    WRITE_HELPER_RET(parcel, String, sn_, false);
    WRITE_HELPER_RET(parcel, String, productId_, false);
    WRITE_HELPER_RET(parcel, String, subProductId_, false);
    WRITE_HELPER_RET(parcel, String, hiv_, false);
    WRITE_HELPER_RET(parcel, String, mac_, false);
    WRITE_HELPER_RET(parcel, String, fwv_, false);
    WRITE_HELPER_RET(parcel, String, hwv_, false);
    WRITE_HELPER_RET(parcel, String, swv_, false);
    WRITE_HELPER_RET(parcel, Int32, protType_, false);
    WRITE_HELPER_RET(parcel, String, wiseUserId_, false);
    WRITE_HELPER_RET(parcel, String, wiseDeviceId_, false);
    WRITE_HELPER_RET(parcel, String, registerTime_, false);
    WRITE_HELPER_RET(parcel, String, modifyTime_, false);
    WRITE_HELPER_RET(parcel, String, shareTime_, false);
    WRITE_HELPER_RET(parcel, String, accountId_, false);
    WRITE_HELPER_RET(parcel, String, innerModel_, false);
    WRITE_HELPER_RET(parcel, String, bleMac_, false);
    WRITE_HELPER_RET(parcel, String, brMac_, false);
    WRITE_HELPER_RET(parcel, String, sleMac_, false);
    WRITE_HELPER_RET(parcel, Int32, setupType_, false);
    return true;
}

bool DeviceProfile::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, deviceId_, false);
    READ_HELPER_RET(parcel, String, deviceName_, false);
    READ_HELPER_RET(parcel, String, manufactureName_, false);
    READ_HELPER_RET(parcel, String, deviceModel_, false);
    READ_HELPER_RET(parcel, Int64, storageCapability_, false);
    READ_HELPER_RET(parcel, String, osSysCap_, false);
    READ_HELPER_RET(parcel, Int32, osApiLevel_, false);
    READ_HELPER_RET(parcel, String, osVersion_, false);
    READ_HELPER_RET(parcel, Int32, osType_, false);
    READ_HELPER_RET(parcel, Bool, isMultiUser_, false);
    READ_HELPER_RET(parcel, Int32, userId_, false);
    READ_HELPER_RET(parcel, String, devType_, false);
    READ_HELPER_RET(parcel, String, manu_, false);
    READ_HELPER_RET(parcel, String, sn_, false);
    READ_HELPER_RET(parcel, String, productId_, false);
    READ_HELPER_RET(parcel, String, subProductId_, false);
    READ_HELPER_RET(parcel, String, hiv_, false);
    READ_HELPER_RET(parcel, String, mac_, false);
    READ_HELPER_RET(parcel, String, fwv_, false);
    READ_HELPER_RET(parcel, String, hwv_, false);
    READ_HELPER_RET(parcel, String, swv_, false);
    READ_HELPER_RET(parcel, Int32, protType_, false);
    READ_HELPER_RET(parcel, String, wiseUserId_, false);
    READ_HELPER_RET(parcel, String, wiseDeviceId_, false);
    READ_HELPER_RET(parcel, String, registerTime_, false);
    READ_HELPER_RET(parcel, String, modifyTime_, false);
    READ_HELPER_RET(parcel, String, shareTime_, false);
    READ_HELPER_RET(parcel, String, accountId_, false);
    READ_HELPER_RET(parcel, String, innerModel_, false);
    READ_HELPER_RET(parcel, String, bleMac_, false);
    READ_HELPER_RET(parcel, String, brMac_, false);
    READ_HELPER_RET(parcel, String, sleMac_, false);
    READ_HELPER_RET(parcel, Int32, setupType_, false);
    return true;
}

bool DeviceProfile::operator!=(const DeviceProfile& deviceProfile) const
{
    bool isNotEqual = (deviceId_ != deviceProfile.GetDeviceId() || deviceName_ != deviceProfile.GetDeviceName() ||
        manufactureName_ != deviceProfile.GetManufactureName() || deviceModel_ != deviceProfile.GetDeviceModel() ||
        storageCapability_ != deviceProfile.GetStorageCapability() || osSysCap_ != deviceProfile.GetOsSysCap() ||
        osApiLevel_ != deviceProfile.GetOsApiLevel() || osVersion_ != deviceProfile.GetOsVersion() ||
        osType_ != deviceProfile.GetOsType() || isMultiUser_ != deviceProfile.IsMultiUser() ||
        userId_ != deviceProfile.GetUserId() || devType_ != deviceProfile.GetDevType() ||
        manu_ != deviceProfile.GetManu() || sn_ != deviceProfile.GetSn() ||
        productId_ != deviceProfile.GetProductId() || subProductId_ != deviceProfile.GetSubProductId() ||
        hiv_ != deviceProfile.GetHiv() || mac_ != deviceProfile.GetMac() ||
        fwv_ != deviceProfile.GetFwv() || hwv_ != deviceProfile.GetHwv() ||
        swv_ != deviceProfile.GetSwv() || protType_ != deviceProfile.GetProtType() ||
        wiseUserId_ != deviceProfile.GetWiseUserId() || wiseDeviceId_ != deviceProfile.GetWiseDeviceId() ||
        registerTime_ != deviceProfile.GetRegisterTime() || innerModel_ != deviceProfile.GetInnerModel() ||
        modifyTime_ != deviceProfile.GetModifyTime() || shareTime_ != deviceProfile.GetShareTime() ||
        accountId_ != deviceProfile.GetAccountId() || id_ != deviceProfile.GetId() ||
        bleMac_ != deviceProfile.bleMac_ || brMac_ != deviceProfile.brMac_ || sleMac_ != deviceProfile.sleMac_ ||
        setupType_ != deviceProfile.setupType_);
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
    cJSON_AddStringToObject(json, DEVICE_NAME.c_str(), ProfileUtils::GetAnonyString(deviceName_).c_str());
    cJSON_AddStringToObject(json, MANUFACTURE_NAME.c_str(), manu_ .c_str());
    cJSON_AddStringToObject(json, DEVICE_MODEL.c_str(), deviceModel_.c_str());
    cJSON_AddNumberToObject(json, STORAGE_CAPACITY.c_str(), storageCapability_);
    cJSON_AddStringToObject(json, OS_SYS_CAPACITY.c_str(), osSysCap_.c_str());
    cJSON_AddNumberToObject(json, OS_API_LEVEL.c_str(), osApiLevel_);
    cJSON_AddStringToObject(json, OS_VERSION.c_str(), osVersion_.c_str());
    cJSON_AddStringToObject(json, INNER_MODEL.c_str(), innerModel_.c_str());
    cJSON_AddNumberToObject(json, OS_TYPE.c_str(), osType_);
    cJSON_AddBoolToObject(json, IS_MULTI_USER.c_str(), isMultiUser_);
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
    cJSON_AddStringToObject(json, DEVICE_NAME.c_str(), ProfileUtils::GetAnonyString(deviceName_).c_str());
    cJSON_AddStringToObject(json, MANUFACTURE_NAME.c_str(), manu_.c_str());
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
    cJSON_AddBoolToObject(json, IS_MULTI_USER.c_str(), isMultiUser_);
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
} // namespace DistributedDeviceProfile
} // namespace OHOS
