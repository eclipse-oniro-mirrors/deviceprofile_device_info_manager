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

#include "device_manager.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dm_dev_trust_change_callback.h"
#include "dm_device_state_callback.h"
#include "dp_dm_init_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DMAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(DMAdapter);

int32_t DMAdapter::Init()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (dmInitCallback_ == nullptr) {
            dmInitCallback_ = std::make_shared<DpDmInitCallback>();
        }
        if (deviceStateCallback_ == nullptr) {
            deviceStateCallback_ = std::make_shared<DmDeviceStateCallback>();
        }
        if (devTrustChangeCallback_ == nullptr) {
            devTrustChangeCallback_ = std::make_shared<DmDevTrustChangeCallback>();
        }
        int32_t errCode = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(
            DP_PKG_NAME, dmInitCallback_);
        if (errCode != DP_SUCCESS) {
            HILOGE("InitDeviceManager errCode = %{public}d", errCode);
            return errCode;
        }
        errCode = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(
            DP_PKG_NAME, "", deviceStateCallback_);
        if (errCode != DP_SUCCESS) {
            HILOGE("RegisterDevStateCallback errCode = %{public}d", errCode);
            return errCode;
        }
        errCode = DistributedHardware::DeviceManager::GetInstance().RegDevTrustChangeCallback(
            DP_PKG_NAME, devTrustChangeCallback_);
        if (errCode != DP_SUCCESS) {
            HILOGE("RegDevTrustChangeCallback errCode = %{public}d", errCode);
        }
    }
    return DP_SUCCESS;
}

int32_t DMAdapter::UnInit()
{
    HILOGI("call!");
    int32_t errCode = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (deviceStateCallback_ != nullptr) {
            errCode = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(DP_PKG_NAME);
            HILOGI("UnRegisterDevStateCallback errCode = %{public}d", errCode);
            deviceStateCallback_ = nullptr;
        }
        if (dmInitCallback_ != nullptr) {
            errCode = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(DP_PKG_NAME);
            HILOGI("UnInitDeviceManager errCode = %{public}d", errCode);
            dmInitCallback_ = nullptr;
        }
    }
    return DP_SUCCESS;
}

int32_t DMAdapter::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

bool DMAdapter::GetUuidByNetworkId(const std::string& networkId, std::string& uuid)
{
    return ((DistributedHardware::DeviceManager::GetInstance().GetUuidByNetworkId(DP_PKG_NAME, networkId, uuid) == 0) ?
        true : false);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS