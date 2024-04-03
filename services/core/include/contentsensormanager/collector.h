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

#ifndef OHOS_DP_PROFILE_CONTENT_COLLECTOR_H
#define OHOS_DP_PROFILE_CONTENT_COLLECTOR_H
#include <vector>
#include "characteristic_profile.h"
#include "device_profile.h"
#include "service_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class Collector {
public:
    Collector() = default;
    virtual ~Collector() = default;
    virtual bool ConvertToProfile(DeviceProfile& deviceProfile);
    virtual bool ConvertToProfile(std::vector<ServiceProfile>& svrProfileList);
    virtual bool ConvertToProfile(std::vector<CharacteristicProfile>& charProfileList);

    void Collect(const DeviceProfile& deviceProfile);
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_PROFILE_CONTENT_COLLECTOR_H