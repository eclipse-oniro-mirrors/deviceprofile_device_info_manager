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

#include "dm_device_state_callback.h"

#include "cJSON.h"
#include "dm_constants.h"

#include "distributed_device_profile_log.h"
#include "device_profile_manager.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DmDeviceStateCallback";
}

void DmDeviceStateCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo)
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

void DmDeviceStateCallback::OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    std::string networkId = deviceInfo.networkId;
    HILOGI("networkId:%{public}s", ProfileUtils::GetAnonyString(networkId).c_str());
    ProfileCache::GetInstance().OnNodeOffline(networkId);
}

void DmDeviceStateCallback::OnDeviceChanged(const DistributedHardware::DmDeviceInfo& deviceInfo)
{}

void DmDeviceStateCallback::OnDeviceReady(const DistributedHardware::DmDeviceInfo& deviceInfo)
{}

bool DmDeviceStateCallback::ConvertToTrustedDeviceInfo(const DistributedHardware::DmDeviceInfo& deviceInfo,
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
} // namespace DistributedDeviceProfile
} // namespace OHOS