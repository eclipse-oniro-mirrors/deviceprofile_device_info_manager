/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_service.h"

#include "device_manager.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "service_characteristic_profile.h"
#include "subscribe_manager.h"

#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileService";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileService);
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DistributedDeviceProfileService::GetInstance());

DistributedDeviceProfileService::DistributedDeviceProfileService()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true)
{
}

bool DistributedDeviceProfileService::Init()
{
    if (!DeviceManager::GetInstance().Init()) {
        HILOGE("DeviceManager init failed");
        return false;
    }
    if (!DeviceProfileStorageManager::GetInstance().Init()) {
        HILOGE("DeviceProfileStorageManager init failed");
        return false;
    }
    if (!SubscribeManager::GetInstance().Init()) {
        HILOGE("SubscribeManager init failed");
        return false;
    }
    HILOGI("init succeeded");
    return true;
}

int32_t DistributedDeviceProfileService::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    return DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
}

int32_t DistributedDeviceProfileService::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    return DeviceProfileStorageManager::GetInstance().GetDeviceProfile(udid, serviceId, profile);
}

int32_t DistributedDeviceProfileService::DeleteDeviceProfile(const std::string& serviceId)
{
    HILOGI("service id %{public}s", serviceId.c_str());
    return DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile(serviceId);
}

int32_t DistributedDeviceProfileService::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    return SubscribeManager::GetInstance().SubscribeProfileEvents(subscribeInfos,
        profileEventNotifier, failedEvents);
}

int32_t DistributedDeviceProfileService::UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    return SubscribeManager::GetInstance().UnsubscribeProfileEvents(profileEvents,
        profileEventNotifier, failedEvents);
}
void DistributedDeviceProfileService::OnStart()
{
    HILOGI("called");
    if (!Init()) {
        HILOGE("init failed");
        return;
    }
    if (!Publish(this)) {
        HILOGE("publish SA failed");
        return;
    }
}

void DistributedDeviceProfileService::OnStop()
{
    HILOGI("called");
}
} // namespace DeviceProfile
} // namespace OHOS