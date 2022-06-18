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
    const char* model = GetProductModel();
    if (model == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceModel = model;
    free((char*)model);
    return deviceModel;
}

std::string DeviceInfoCollector::GetDevType()
{
    const char* type = GetDeviceType();
    if (type == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceType = type;
    free((char*)type);
    return deviceType;
}

std::string DeviceInfoCollector::GetDeviceManufacturer()
{
    const char* facture = GetManufacture();
    if (facture == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string manuFacture = facture;
    free((char*)facture);
    return manuFacture;
}

std::string DeviceInfoCollector::GetDeviceSerial()
{
    const char* serial = GetSerial();
    if (serial == nullptr) {
        HILOGE("get failed");
        return EMPTY_PARAM;
    }
    std::string deviceSerial = serial;
    free((char*)serial);
    return deviceSerial;
}

std::string DeviceInfoCollector::GetDeviceName()
{
    const char* name = GetMarketName();
    if (name == nullptr) {
        return GetDeviceModel();
    }
    std::string devName = name;
    free((char*)name);
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