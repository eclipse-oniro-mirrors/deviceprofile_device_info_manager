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

#include "switch_profile_manager.h"

#include <algorithm>
#include <dlfcn.h>
#include <mutex>
#include <memory>
#include <vector>

#include "switch_adapter.h"
#include "content_sensor_manager_utils.h"
#include "device_manager.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "profile_control_utils.h"
#include "permission_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SwitchProfileManager);
namespace {
    const std::string TAG = "SwitchProfileManager";
    const std::string APP_ID = "distributed_device_profile_service";
}

int32_t SwitchProfileManager::Init()
{
    HILOGI("call!");
    SwitchAdapter::GetInstance().Init();
    int32_t res = SwitchAdapter::GetInstance().SubscribeSwitchData(APP_ID);
    if (res != DP_SUCCESS) {
        HILOGE("SubscribeSwitchData failed, res: %d", res);
        return DP_INIT_SWITCH_PROFILE_MANAGER_FAIL;
    }
    return DP_SUCCESS;
}

int32_t SwitchProfileManager::UnInit()
{
    HILOGI("call!");
    int32_t res = SwitchAdapter::GetInstance().UnsubscribeSwitchData(APP_ID);
    if (res != DP_SUCCESS) {
        HILOGE("UnsubscribeSwitchData failed, res: %d", res);
        return DP_UNSUBSCRIBE_FAILED;
    }
    return DP_SUCCESS;
}

int32_t SwitchProfileManager::ReInit()
{
    HILOGI("call!");
    UnInit();
    return Init();
}

int32_t SwitchProfileManager::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(switchProfileMutex_);
        res = ProfileControlUtils::PutSwitchCharacteristicProfile(APP_ID, charProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t SwitchProfileManager::PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(switchProfileMutex_);
        res = ProfileControlUtils::PutSwitchCharacteristicProfileBatch(APP_ID, charProfiles);
    }
    if (res != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfileBatch fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("PutCharacteristicProfileBatch success");
    return DP_SUCCESS;
}

int32_t SwitchProfileManager::GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
    const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    HILOGI("call!");
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(switchProfileMutex_);
        res = ProfileControlUtils::GetSwitchCharacteristicProfile(APP_ID, deviceId, serviceName, characteristicKey,
            charProfile);
    }
    if (res != DP_SUCCESS) {
        HILOGE("GetSwitchCharacteristicProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetSwitchCharacteristicProfile success");
    return DP_SUCCESS;
}

int32_t SwitchProfileManager::RefreshLocalSwitchProfile()
{
    HILOGI("call!");
    int32_t res = ProfileControlUtils::RefreshLocalSwitchProfile(APP_ID);
    if (res != DP_SUCCESS) {
        HILOGE("RefreshLocalSwitchProfile fail, reason: %{public}d!", res);
        return res;
    }
    HILOGI("GetSwitchCharacteristicProfile success");
    return DP_SUCCESS;
}

} // namespace DistributedDeviceProfile
} // namespace OHOS
