/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "device_info_collector.h"

#include "device_profile_log.h"
#include "nlohmann/json.hpp"
#include "parameter.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DeviceInfoCollector";

const std::string SERVICE_ID = "device";
const std::string SERVICE_TYPE = "device";
const std::string EMPTY_PARAM = "";
const std::string DEVICE_NAME = "deviceName";
const std::string DEVICE_MODEL = "model";
const std::string DEVICE_UDID = "udid";
const std::string DEVICE_TYPE = "devType";
const std::string DEVICE_MANU = "manu";
const std::string DEVICE_SN = "sn";
constexpr int32_t DEVICE_UUID_LENGTH = 65;
}

bool DeviceInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    jsonData[DEVICE_NAME] = GetDeviceName();
    jsonData[DEVICE_MODEL] = GetDeviceModel();
    jsonData[DEVICE_UDID] = GetDeviceUdid();
    jsonData[DEVICE_TYPE] = GetDevType();
    jsonData[DEVICE_MANU] = GetDeviceManufacturer();
    jsonData[DEVICE_SN] = GetDeviceSerial();
    profile.SetCharacteristicProfileJson(jsonData.dump());
    return true;
}

std::string DeviceInfoCollector::GetDeviceModel()
{
    // The pointer is const in the interface. So no longer free char* productModelTempl.
    const char* productModelTempl = GetProductModel();
    if (productModelTempl == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceModel = productModelTempl;
    return deviceModel;
}

std::string DeviceInfoCollector::GetDevType()
{
    // The pointer is const in the interface. So no longer free char* deviceTypeTempl.
    const char* deviceTypeTempl = GetDeviceType();
    if (deviceTypeTempl == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceType = deviceTypeTempl;
    return deviceType;
}

std::string DeviceInfoCollector::GetDeviceManufacturer()
{
    // The pointer is const in the interface. So no longer free char* manuFactureTempl.
    const char* manuFactureTempl = GetManufacture();
    if (manuFactureTempl == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string manuFacture = manuFactureTempl;
    return manuFacture;
}

std::string DeviceInfoCollector::GetDeviceSerial()
{
    // The pointer is const in the interface. So no longer free char* serialTempl.
    const char* serialTempl = GetSerial();
    if (serialTempl == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceSerial = serialTempl;
    return deviceSerial;
}

std::string DeviceInfoCollector::GetDeviceName()
{
    // The pointer is const in the interface. So no longer free char* marketNameTempl.
    const char* marketNameTempl = GetMarketName();
    if (marketNameTempl == nullptr) {
        return GetDeviceModel();
    }
    std::string devName = marketNameTempl;
    if (!devName.empty()) {
        return devName;
    }
    return GetDeviceModel();
}

std::string DeviceInfoCollector::GetDeviceUdid()
{
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    return localDeviceId;
}
} // namespace DeviceProfile
} // namespace OHOS