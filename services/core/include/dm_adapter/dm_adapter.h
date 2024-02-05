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

#include "single_instance.h"

#include "device_manager.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DMAdapter {
DECLARE_SINGLE_INSTANCE(DMAdapter);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    void AutoSync(const DistributedHardware::DmDeviceInfo &deviceInfo);

private:
    std::mutex deviceStateCallbackMutex_;
    std::shared_ptr<DistributedHardware::DeviceStateCallback> deviceStateCallback_;
    std::mutex autoSyncHandlerMutex_;
    std::shared_ptr<AppExecFwk::EventHandler> autoSyncHandler_;
class DpDeviceStateCallback : public DistributedHardware::DeviceStateCallback {
    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
};
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DM_ADAPTER_H
