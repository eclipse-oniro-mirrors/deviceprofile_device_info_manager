/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "i_profile_change_listener.h"
#include "distributed_device_profile_errors.h"


namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "IProfileChangeListener";
}
int32_t IProfileChangeListener::OnTrustDeviceProfileActive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t IProfileChangeListener::OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS