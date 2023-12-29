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

#include "device_profile.h"
#include "distributed_device_profile_log.h"
#include "nlohmann/json.hpp"
#include "parameter.h"
#include "content_sensor_manager_utils.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "DeviceInfoCollector";
}

bool DeviceInfoCollector::ConvertToProfile(DeviceProfile& deviceProfile)
{
    HILOGI("called!");
    deviceProfile.SetDeviceId(GetLocalUdidFromDM());
    deviceProfile.SetDeviceName(GetDeviceName());
    deviceProfile.SetDeviceModel(GetDeviceModel());
    deviceProfile.SetDeviceTypeName(GetDevType());
    deviceProfile.SetManufactureName(GetDeviceManufacturer());
    deviceProfile.SetSerialNumberId(GetDeviceSerial());
    return true;
}

std::string DeviceInfoCollector::GetDeviceModel()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainProductModel();
}

std::string DeviceInfoCollector::GetDevType()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainDeviceType();
}

std::string DeviceInfoCollector::GetDeviceManufacturer()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainManufacture();
}

std::string DeviceInfoCollector::GetDeviceSerial()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainSerial();
}

std::string DeviceInfoCollector::GetDeviceName()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainMarketName();
}

std::string DeviceInfoCollector::GetDeviceUdid()
{
    HILOGI("called!");
    return DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
}
} // namespace DeviceProfile
} // namespace OHOS