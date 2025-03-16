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

#ifndef OHOS_DP_PROFILE_SYSTEM_INFO_COLLECTOR_H
#define OHOS_DP_PROFILE_SYSTEM_INFO_COLLECTOR_H

#include <string>
#include <map>

#include "collector.h"
#include "device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SystemInfoCollector : public Collector {
public:
    bool ConvertToProfile(DeviceProfile& profile) override;

private:
    const std::map<std::string, std::string> deviceTypeMap = {
        {TYPE_UNKNOWN, "00A"},
        {TYPE_PHONE, "00E"},
        {TYPE_PAD, "011"},
        {TYPE_TV, "09C"},
        {TYPE_CAR, "083"},
        {TYPE_WATCH, "06D"},
        {TYPE_PC, "00C"},
        {TYPE_2IN1, "A2F"}
    };
    int32_t GetOsType();
    int32_t GetProtType();
    std::string GetOsVersion();
    std::string GetDeviceName();
    std::string GetProductId();
    std::string GetProductName();
    std::string GetSn();
    std::string GetDeviceModel();
    std::string GetDevType();
    std::string GetDeviceManufacturer();
    std::string GetDeviceTypeId();
    std::string GetSubProductId();
    std::string DecodeHexStr(const std::string &str);
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_SYSTEM_INFO_COLLECTOR_H
