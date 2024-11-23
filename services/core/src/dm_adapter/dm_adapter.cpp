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
#include "device_manager.h"
#include "dm_constants.h"

#include "device_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "profile_cache.h"
#include "profile_utils.h"

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

void DMAdapter::DmDeviceStateCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    HILOGI("networkId:%{public}s", ProfileUtils::GetAnonyString(deviceInfo.networkId).c_str());
    TrustedDeviceInfo trustedDeviceInfo;
    if (!ConvertToTrustedDeviceInfo(deviceInfo, trustedDeviceInfo)) {
        return;
    }
    HILOGI("trustedDeviceInfo:%{public}s", trustedDeviceInfo.dump().c_str());
    ProfileCache::GetInstance().OnNodeOnline(trustedDeviceInfo);
    DeviceProfileManager::GetInstance().OnDeviceOnline(trustedDeviceInfo);
}

void DMAdapter::DmDeviceStateCallback::OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = deviceInfo.networkId;
    HILOGI("networkId:%{public}s", ProfileUtils::GetAnonyString(networkId).c_str());
    ProfileCache::GetInstance().OnNodeOffline(networkId);
}

void DMAdapter::DmDeviceStateCallback::OnDeviceChanged(const DistributedHardware::DmDeviceInfo& deviceInfo)
{}

void DMAdapter::DmDeviceStateCallback::OnDeviceReady(const DistributedHardware::DmDeviceInfo& deviceInfo)
{}

bool DMAdapter::DmDeviceStateCallback::ConvertToTrustedDeviceInfo(const DistributedHardware::DmDeviceInfo& deviceInfo,
    TrustedDeviceInfo& trustedDeviceInfo)
{
    trustedDeviceInfo.SetNetworkId(deviceInfo.networkId);
    trustedDeviceInfo.SetAuthForm(static_cast<int32_t>(deviceInfo.authForm));
    trustedDeviceInfo.SetDeviceTypeId(deviceInfo.deviceTypeId);

    if (deviceInfo.extraData.empty()) {
        HILOGE("extraData is empty!");
        return false;
    }
    cJSON* extraDataJson = cJSON_Parse(deviceInfo.extraData.c_str());
    if (extraDataJson == NULL) {
        HILOGE("extraData parse failed");
        cJSON_Delete(extraDataJson);
        return false;
    }

    cJSON* osVersionJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_OS_VERSION);
    if (!cJSON_IsString(osVersionJson)) {
        HILOGE("osVersion parse failed");
        cJSON_Delete(extraDataJson);
        return false;
    }
    trustedDeviceInfo.SetOsVersion(osVersionJson->valuestring);

    cJSON* osTypeJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_OS_TYPE);
    if (!cJSON_IsNumber(osTypeJson)) {
        HILOGE("osType parse failed");
        cJSON_Delete(extraDataJson);
        return false;
    }
    trustedDeviceInfo.SetOsType(static_cast<int32_t>(osTypeJson->valueint));

    cJSON* udidJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_UDID);
    if (!cJSON_IsString(udidJson)) {
        HILOGE("udid parse failed");
        cJSON_Delete(extraDataJson);
        return false;
    }
    trustedDeviceInfo.SetUdid(udidJson->valuestring);

    cJSON* uuidJson = cJSON_GetObjectItem(extraDataJson, DistributedHardware::PARAM_KEY_UUID);
    if (!cJSON_IsString(uuidJson)) {
        HILOGE("uuid parse failed");
        cJSON_Delete(extraDataJson);
        return false;
    }
    trustedDeviceInfo.SetUuid(uuidJson->valuestring);
    cJSON_Delete(extraDataJson);
    return true;
}

void DMAdapter::DpDmInitCallback::OnRemoteDied()
{
    HILOGI("call!");
    DMAdapter::GetInstance().ReInit();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS