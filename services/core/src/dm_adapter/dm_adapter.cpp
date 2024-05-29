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
#include "cJSON.h"
#include "device_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "event_handler_factory.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DMAdapter";
    const std::string AUTO_SYNC_TASK = "autoSyncTask";
    const int32_t DEFAULT_OS_TYPE = 10;
    constexpr const char* OS_TYPE_KEY = "OS_TYPE";
    const std::string PKGNAME = "DMAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(DMAdapter);

int32_t DMAdapter::Init()
{
    HILOGI("call!");
    int32_t errCode = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> lock(autoSyncHandlerMutex_);
        if (autoSyncHandler_ == nullptr) {
            autoSyncHandler_ = EventHandlerFactory::GetInstance().CreateEventHandler(AUTO_SYNC_HANDLER);
        }
        if (autoSyncHandler_ == nullptr) {
            HILOGE("Create EventHandler is failed, handlerName: %{public}s!", AUTO_SYNC_HANDLER.c_str());
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (deviceStateCallback_ == nullptr) {
            deviceStateCallback_ = std::make_shared<DpDeviceStateCallback>();
        }
        errCode = DistributedHardware::DeviceManager::GetInstance()
            .RegisterDevStateCallback(PKGNAME, "", deviceStateCallback_);
    }
    HILOGI("RegisterDevStateCallback errCode = %{public}d", errCode);
    return errCode;
}

int32_t DMAdapter::UnInit()
{
    HILOGI("call!");
    int32_t errCode = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> lock(autoSyncHandlerMutex_);
        if (autoSyncHandler_ != nullptr) {
            autoSyncHandler_->RemoveTask(AUTO_SYNC_TASK);
            autoSyncHandler_ = nullptr;
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(deviceStateCallbackMutex_);
        if (deviceStateCallback_ != nullptr) {
            errCode = DistributedHardware::DeviceManager::GetInstance().UnRegisterDevStateCallback(PKGNAME);
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

void DMAdapter::AutoSync(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call! networdId=%{public}s", ProfileUtils::GetAnonyString(deviceInfo.networkId).c_str());
    if (deviceInfo.extraData.empty()) {
        HILOGE("extraData is empty!");
        return;
    }
    auto autoSyncTask = [deviceInfo]() {
        cJSON* extraData = cJSON_Parse(deviceInfo.extraData.c_str());
        if (!cJSON_IsObject(extraData)) {
            HILOGE("extraData parse failed");
            cJSON_Delete(extraData);
            return;
        }
        int32_t osType = DEFAULT_OS_TYPE;
        cJSON* osTypeJson = cJSON_GetObjectItem(extraData, OS_TYPE_KEY);
        if (cJSON_IsNumber(osTypeJson)) {
            osType = static_cast<int32_t>(osTypeJson->valueint);
        }
        cJSON_Delete(extraData);
        HILOGI("osType=%{public}d", osType);
        if (osType != DEFAULT_OS_TYPE) {
            int32_t errCode = DeviceProfileManager::GetInstance().DeviceOnlineAutoSync(deviceInfo.networkId);
            HILOGI("DeviceOnlineAutoSync errCode=%{public}d, networdId=%{public}s", errCode,
                ProfileUtils::GetAnonyString(deviceInfo.networkId).c_str());
        }
    };
    {
        std::lock_guard<std::mutex> lock(autoSyncHandlerMutex_);
        if (autoSyncHandler_ == nullptr) {
            HILOGE("Create EventHandler is nullptr, handlerName: %{public}s!", AUTO_SYNC_HANDLER.c_str());
            return;
        }
        if (!autoSyncHandler_->PostTask(autoSyncTask, AUTO_SYNC_TASK, 0)) {
            HILOGE("Post autoSyncTask fail!");
            return;
        }
    }
}

void DMAdapter::DpDeviceStateCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    HILOGI("call!");
    DMAdapter::GetInstance().AutoSync(deviceInfo);
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