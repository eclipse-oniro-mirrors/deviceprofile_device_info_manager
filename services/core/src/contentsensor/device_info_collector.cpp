/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "device_profile_errors.h"
#include "device_profile_log.h"

#include "nlohmann/json.hpp"
#include "parameter.h"
#include "parameters.h"

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
const std::string DEVICE_PRODUCT_ID = "prodId";
const std::string DEVICE_SN = "sn";
const std::string DEVICE_NAME_PARAM = "ro.product.name";
const std::string DEVICE_TYPE_PARAM = "ro.build.characteristics";
constexpr int32_t DEVICE_UUID_LENGTH = 65;
}

void DeviceInfoCollector::ConvertToProfileData(ServiceCharacteristicProfile& profile)
{
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    nlohmann::json jsonData;
    jsonData[DEVICE_NAME] = GetDeviceName();
    jsonData[DEVICE_MODEL] = GetDeviceModel();
    jsonData[DEVICE_UDID] = GetDeviceUdid();
    jsonData[DEVICE_TYPE] = GetDeviceType();
    jsonData[DEVICE_MANU] = GetDeviceManufacturer();
    jsonData[DEVICE_PRODUCT_ID] = GetDeviceProductId();
    jsonData[DEVICE_SN] = GetDeviceSerial();
    profile.SetCharacteristicProfileJson(jsonData.dump());
}

std::string DeviceInfoCollector::GetDeviceModel()
{
    return GetProductModel();
}

std::string DeviceInfoCollector::GetDeviceManufacturer()
{
    return GetManufacture();
}

std::string DeviceInfoCollector::GetDeviceSerial()
{
    return GetSerial();
}

std::string DeviceInfoCollector::GetDeviceType()
{
    return system::GetParameter(DEVICE_TYPE_PARAM, EMPTY_PARAM);
}

std::string DeviceInfoCollector::GetDeviceName()
{
    std::string devName = system::GetParameter(DEVICE_NAME_PARAM, EMPTY_PARAM);
    if (!devName.empty()) {
        return devName;
    }
    return GetProductModel();
}

std::string DeviceInfoCollector::GetDeviceUdid()
{
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH);
    return localDeviceId;
}

std::string DeviceInfoCollector::GetDeviceProductId()
{
    return "";
}
} // namespace DeviceProfile
} // namespace OHOS