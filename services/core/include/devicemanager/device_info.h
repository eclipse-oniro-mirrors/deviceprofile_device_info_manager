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

#ifndef OHOS_DEVICE_PROFILE_DEVICE_INFO_H
#define OHOS_DEVICE_PROFILE_DEVICE_INFO_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace DeviceProfile {
enum {
    UNKNOWN_TYPE = 0x00,
};

class DeviceInfo {
public:
    DeviceInfo(const std::string& deviceName, const std::string& deviceId, int32_t deviceType)
        : deviceName_(deviceName), deviceId_(deviceId), deviceType_(deviceType) {}
    ~DeviceInfo() = default;

    const std::string& GetDeviceName() const;
    const std::string& GetDeviceId() const;
    int32_t GetDeviceType() const;

private:
    std::string deviceName_;
    std::string deviceId_;
    int32_t deviceType_ = UNKNOWN_TYPE;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_PROFILE_DEVICE_INFO_H
