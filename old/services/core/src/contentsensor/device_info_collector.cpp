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
#include "content_sensor_manager_utils.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DeviceInfoCollector";

const std::string SERVICE_ID = "device";
const std::string SERVICE_TYPE = "device";
const std::string DEVICE_NAME = "deviceName";
const std::string DEVICE_MODEL = "model";
const std::string DEVICE_UDID = "udid";
const std::string DEVICE_TYPE = "devType";
const std::string DEVICE_MANU = "manu";
const std::string DEVICE_SN = "sn";
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
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainProductModel();
}

std::string DeviceInfoCollector::GetDevType()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDeviceType();
}

std::string DeviceInfoCollector::GetDeviceManufacturer()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainManufacture();
}

std::string DeviceInfoCollector::GetDeviceSerial()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainSerial();
}

std::string DeviceInfoCollector::GetDeviceName()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainMarketName();
}

std::string DeviceInfoCollector::GetDeviceUdid()
{
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
}
} // namespace DeviceProfile
} // namespace OHOS