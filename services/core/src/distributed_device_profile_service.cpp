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

#include "file_ex.h"
#include "string_ex.h"

#include "authority_manager.h"
#include "content_sensor_manager.h"
#include "device_profile_dumper.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "dp_device_manager.h"
#include "hitrace_meter.h"
#include "service_characteristic_profile.h"
#include "subscribe_manager.h"
#include "system_ability_definition.h"
#include "trust_group_manager.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileService";
const std::string DP_DEVICE_SUB_TRACE = "DP_DEVICE_SUB";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileService);
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DistributedDeviceProfileService::GetInstance());

DistributedDeviceProfileService::DistributedDeviceProfileService()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true)
{
}

bool DistributedDeviceProfileService::Init()
{
    if (!DpDeviceManager::GetInstance().Init()) {
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
    if (!AuthorityManager::GetInstance().Init()) {
        HILOGE("AuthorityManager init failed");
        return false;
    }
    TrustGroupManager::GetInstance().InitHichainService();
    ContentSensorManager::GetInstance().Init();
    HILOGI("init succeeded");
    return true;
}

int32_t DistributedDeviceProfileService::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    if (!AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        profile.GetServiceId())) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
}

int32_t DistributedDeviceProfileService::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    if (!AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        serviceId)) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().GetDeviceProfile(udid, serviceId, profile);
}

int32_t DistributedDeviceProfileService::DeleteDeviceProfile(const std::string& serviceId)
{
    if (!AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        serviceId)) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile(serviceId);
}

int32_t DistributedDeviceProfileService::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    HITRACE_METER_NAME(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_SUB_TRACE);
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

int32_t DistributedDeviceProfileService::SyncDeviceProfile(const SyncOptions& syncOptions,
    const sptr<IRemoteObject>& profileEventNotifier)
{
    if (!AuthorityManager::GetInstance().CheckInterfaceAuthority("sync")) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().SyncDeviceProfile(syncOptions, profileEventNotifier);
}

int32_t DistributedDeviceProfileService::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    std::vector<std::string> argsInStr8;
    for (const auto& arg : args) {
        argsInStr8.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    DeviceProfileDumper::Dump(argsInStr8, result);

    if (!SaveStringToFd(fd, result)) {
        HILOGE("save to fd failed");
        return ERR_DP_FILE_FAILED_ERR;
    }
    return ERR_OK;
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