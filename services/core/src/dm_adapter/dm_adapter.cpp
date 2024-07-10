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

#include "dm_adapter.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DMAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(DMAdapter);

int32_t DMAdapter::Init()
{
    HILOGI("call!");
    int32_t errCode = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (deviceStateCallback_ == nullptr) {
            deviceStateCallback_ = std::make_shared<DpDeviceStateCallback>();
        }
        errCode = DistributedHardware::DeviceManager::GetInstance()
            .RegisterDevStateCallback(DP_PKG_NAME, "", deviceStateCallback_);
    }
    HILOGI("RegisterDevStateCallback errCode = %{public}d", errCode);
    return errCode;
}

int32_t DMAdapter::UnInit()
{
    HILOGI("call!");
    int32_t errCode = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (deviceStateCallback_ != nullptr) {
            errCode = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(DP_PKG_NAME);
            deviceStateCallback_ = nullptr;
        }
    }
    HILOGI("UnRegisterDevStateCallback errCode = %{public}d", errCode);
    return errCode;
}

int32_t DMAdapter::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

void DMAdapter::DpDeviceStateCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call!");
}

void DMAdapter::DpDeviceStateCallback::OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call!");
}

void DMAdapter::DpDeviceStateCallback::OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call!");
}

void DMAdapter::DpDeviceStateCallback::OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call!");
}
} // namespace DistributedDeviceProfile
} // namespace OHOS