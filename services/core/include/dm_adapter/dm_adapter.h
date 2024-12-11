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

#ifndef OHOS_DP_DM_ADAPTER_H
#define OHOS_DP_DM_ADAPTER_H

#include <mutex>

#include "device_manager_callback.h"
#include "dm_device_info.h"

#include "single_instance.h"
#include "trusted_device_info.h"
namespace OHOS {
namespace DistributedDeviceProfile {
class DMAdapter {
DECLARE_SINGLE_INSTANCE(DMAdapter);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    bool GetUuidByNetworkId(const std::string& networkId, std::string& uuid);
private:
    std::mutex deviceStateCallbackMutex_;
    std::shared_ptr<DistributedHardware::DmInitCallback> dmInitCallback_;
    std::shared_ptr<DistributedHardware::DeviceStateCallback> deviceStateCallback_;

class DmDeviceStateCallback : public DistributedHardware::DeviceStateCallback {
public:
    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceChanged(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceReady(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
private:
    bool ConvertToTrustedDeviceInfo(const DistributedHardware::DmDeviceInfo& deviceInfo,
        TrustedDeviceInfo& trustedDeviceInfo);
};
class DpDmInitCallback : public DistributedHardware::DmInitCallback {
public:
    void OnRemoteDied() override;
};
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DM_ADAPTER_H
