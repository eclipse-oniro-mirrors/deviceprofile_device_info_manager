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

#include "system_info_collector.h"

#include "parameter.h"
#include "securec.h"
#include "string_ex.h"

#include "content_sensor_manager_utils.h"
#include "device_profile.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "multi_user_manager.h"
#include "profile_utils.h"
#include "settings_data_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "SystemInfoCollector";
const char* OHOS_API_VERSION = "const.ohos.apiversion";
const char* OHOS_BOOT_SN = "ohos.boot.sn";
const char* OHOS_FULL_NAME = "const.ohos.fullname";
const char* VERSION_SDK = "ro.build.version.sdk";
const char* UNDEFINED_VALUE = "undefined";
constexpr int32_t HO_OS_TYPE = 11;
constexpr uint32_t API_VERSION_LEN = 10;
constexpr uint32_t SN_LEN = 32;
constexpr uint32_t FULL_NAME_LEN = 128;
constexpr uint32_t VERSION_SDK_LEN = 10;
const std::vector<std::string> PRODUCT_NAME_PREFIXS {"485541574549", "687561776569", "e58d8ee4b8ba"};
}

bool SystemInfoCollector::ConvertToProfile(DeviceProfile& profile)
{
    profile.SetOsType(GetOsType());
    profile.SetOsVersion(GetOsVersion());
    profile.SetDeviceName(GetDeviceName());
    profile.SetProductId(GetProductId());
    profile.SetSubProductId(GetSubProductId());
    profile.SetSn(GetSn());
    profile.SetDeviceModel(GetDeviceModel());
    profile.SetDevType(GetDeviceTypeId());
    profile.SetManu(GetDeviceManufacturer());
    profile.SetHiv(HIV_VERSION);
    profile.SetProtType(GetProtType());
    profile.SetProductName(GetProductName());
    return true;
}

int32_t SystemInfoCollector::GetOsType()
{
    char apiVersion[API_VERSION_LEN + 1] = {0};
    GetParameter(OHOS_API_VERSION, UNDEFINED_VALUE, apiVersion, API_VERSION_LEN);
    char bootSN[SN_LEN + 1] = {0};
    GetParameter(OHOS_BOOT_SN, UNDEFINED_VALUE, bootSN, SN_LEN);
    char osFullName[FULL_NAME_LEN + 1] = {0};
    GetParameter(OHOS_FULL_NAME, UNDEFINED_VALUE, osFullName, FULL_NAME_LEN);
    if (strcmp(apiVersion, UNDEFINED_VALUE) != 0 || strcmp(bootSN, UNDEFINED_VALUE) != 0 ||
        strcmp(osFullName, UNDEFINED_VALUE) != 0) {
        HILOGI("apiVersion: %{public}s bootSN: %{public}s osFullName: %{public}s",
            ProfileUtils::GetAnonyString(std::string(apiVersion)).c_str(),
            ProfileUtils::GetAnonyString(std::string(bootSN)).c_str(),
            ProfileUtils::GetAnonyString(std::string(osFullName)).c_str());
        return OHOS_TYPE;
    }
    char versionSDK[VERSION_SDK_LEN + 1] = {0};
    GetParameter(VERSION_SDK, UNDEFINED_VALUE, versionSDK, VERSION_SDK_LEN);
    if (strcmp(versionSDK, UNDEFINED_VALUE) != 0) {
        HILOGI("versionSDK: %{public}s", ProfileUtils::GetAnonyString(std::string(versionSDK)).c_str());
        return HO_OS_TYPE;
    }
    HILOGE("GetOsType fail!");
    return OHOS_TYPE_UNKNOWN;
}

std::string SystemInfoCollector::GetOsVersion()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDisplayVersion();
}

std::string SystemInfoCollector::GetDeviceName()
{
    std::string deviceName = "";
    SettingsDataManager::GetInstance().GetUserDefinedDeviceName(
        MultiUserManager::GetInstance().GetCurrentForegroundUserID(), deviceName);
    if (deviceName.empty()) {
        deviceName = GetProductName();
    }
    HILOGI("deviceName : %{public}s", ProfileUtils::GetAnonyString(deviceName).c_str());
    return deviceName;
}

std::string SystemInfoCollector::GetProductId()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainProductId();
}

std::string SystemInfoCollector::GetProductName()
{
    std::string productName = ContentSensorManagerUtils::GetInstance().ObtainMarketName();
    for (const auto &item : PRODUCT_NAME_PREFIXS) {
        productName = TrimStr(ReplaceStr(productName,
            DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().DecodeHexStr(item), ""));
    }
    HILOGI("productName : %{public}s", ProfileUtils::GetAnonyString(productName).c_str());
    return productName;
}

std::string SystemInfoCollector::GetSubProductId()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().GetSubProductId();
}

std::string SystemInfoCollector::GetSn()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainSerial();
}

std::string SystemInfoCollector::GetDeviceModel()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainProductModel();
}

std::string SystemInfoCollector::GetDevType()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDeviceType();
}

std::string SystemInfoCollector::GetDeviceManufacturer()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainManufacture();
}

int32_t SystemInfoCollector::GetProtType()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().GetProtType();
}

std::string SystemInfoCollector::GetDeviceTypeId()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDeviceTypeId();
}
} // namespace DeviceProfile
} // namespace OHOS
