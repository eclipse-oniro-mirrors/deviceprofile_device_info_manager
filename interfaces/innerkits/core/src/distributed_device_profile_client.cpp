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

#include "distributed_device_profile_client.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileClient";
const std::string JSON_NULL = "null";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileClient);
int32_t DistributedDeviceProfileClient::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    if (CheckProfileInvalidity(profile)) {
        return ERR_DP_INVALID_PARAMS;
    }

    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }
    return dps->PutDeviceProfile(profile);
}

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::GetDeviceProfileService()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    if (dpProxy_ != nullptr) {
        return dpProxy_;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return nullptr;
    }
    auto object = samgrProxy->GetSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
    if (object == nullptr) {
        HILOGE("get service failed");
        return nullptr;
    }
    HILOGI("get service succeeded");
    if (dpDeathRecipient_ == nullptr) {
        dpDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
            new (std::nothrow) DeviceProfileDeathRecipient);
    }
    object->AddDeathRecipient(dpDeathRecipient_);
    dpProxy_ = iface_cast<IDistributedDeviceProfile>(object);
    return dpProxy_;
}

bool DistributedDeviceProfileClient::CheckProfileInvalidity(const ServiceCharacteristicProfile& profile)
{
    return profile.GetServiceId().empty() ||
           profile.GetServiceType().empty() ||
           profile.GetCharacteristicProfileJson().empty() ||
           profile.GetCharacteristicProfileJson() == JSON_NULL;
}
void DistributedDeviceProfileClient::OnServiceDied(const sptr<IRemoteObject>& remote)
{
    HILOGI("called");
    {
        std::lock_guard<std::mutex> lock(serviceLock_);
        dpProxy_ = nullptr;
    }
}

void DistributedDeviceProfileClient::DeviceProfileDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    DistributedDeviceProfileClient::GetInstance().OnServiceDied(remote.promote());
}
} // namespace DeviceProfile
} // namespace OHOS