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

#include "dm_dev_trust_change_callback.h"

#include "device_profile_manager.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DmDevTrustChangeCallback";
}

void DmDevTrustChangeCallback::OnDeviceTrustChange(const std::string& peerUdid, const std::string& peerUuid,
    const DistributedHardware::DmAuthForm authform)
{
    HILOGI("peerUdid:%{public}s,peerUuid:%{public}s,authform:%{public}d",
        ProfileUtils::GetAnonyString(peerUdid).c_str(), ProfileUtils::GetAnonyString(peerUuid).c_str(), authform);
    DeviceProfileManager::GetInstance().OnDeviceTrustChange(peerUdid, peerUuid, authform);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS