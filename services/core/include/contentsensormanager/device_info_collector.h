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

#ifndef OHOS_DP_PROFILE_DEVICE_INFO_TASK_H
#define OHOS_DP_PROFILE_DEVICE_INFO_TASK_H

#include <string>

#include "collector.h"
#include "device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceInfoCollector : public Collector {
public:
    bool ConvertToProfile(DeviceProfile& deviceProfile) override;

private:
    std::string GetDeviceModel();
    std::string GetDeviceManufacturer();
    std::string GetDeviceSerial();
    std::string GetDeviceName();
    std::string GetDeviceUdid();
    std::string GetDeviceProductId();
    std::string GetDevType();
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_DEVICE_INFO_TASK_H