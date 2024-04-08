/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_service_new.h"

#include "file_ex.h"
#include "string_ex.h"

#include "if_system_ability_manager.h"
#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "sa_profiles.h"
#include "system_ability_definition.h"

#include "content_sensor_manager.h"
#include "device_profile_dumper.h"
#include "device_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "dm_adapter.h"
#include "event_handler_factory.h"
#include "permission_manager.h"
#include "profile_cache.h"
#include "subscribe_profile_manager.h"
#include "trust_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileServiceNew";
const std::string UNLOAD_TASK_ID = "unload_dp_svr";
constexpr int32_t DELAY_TIME = 180000;
constexpr int32_t UNLOAD_IMMEDIATELY = 0;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileServiceNew);

DistributedDeviceProfileServiceNew::DistributedDeviceProfileServiceNew()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true)
{
    HILOGE("DPService construct!");
    Init();
}

DistributedDeviceProfileServiceNew::~DistributedDeviceProfileServiceNew()
{
    HILOGE("DPService destruction!");
    UnInit();
}

int32_t DistributedDeviceProfileServiceNew::Init()
{
    if (EventHandlerFactory::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("EventHandlerFactory init failed");
        return DP_CACHE_INIT_FAIL;
    }
    if (PermissionManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("DpDeviceManager init failed");
        return DP_DEVICE_MANAGER_INIT_FAIL;
    }
    if (TrustProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("TrustProfileManager init failed");
        return DP_TRUST_PROFILE_MANAGER_INIT_FAIL;
    }
    if (DeviceProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("DeviceProfileManager init failed");
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (ProfileCache::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("ProfileCache init failed");
        return DP_CACHE_INIT_FAIL;
    }
    if (SubscribeProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("SubscribeProfileManager init failed");
        return DP_SUBSCRIBE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("ContentSensorManager init failed");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    HILOGI("init succeeded");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::UnInit()
{
    if (TrustProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("TrustProfileManager init failed");
        return DP_TRUST_PROFILE_MANAGER_INIT_FAIL;
    }
    if (DeviceProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DeviceProfileManager init failed");
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (ProfileCache::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ProfileCache init failed");
        return DP_CACHE_INIT_FAIL;
    }
    if (PermissionManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DpDeviceManager init failed");
        return DP_DEVICE_MANAGER_INIT_FAIL;
    }
    if (SubscribeProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("SubscribeProfileManager init failed");
        return DP_SUBSCRIBE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ContentSensorManager init failed");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (EventHandlerFactory::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("EventHandlerFactory init failed");
        return DP_CACHE_INIT_FAIL;
    }
    HILOGI("init succeeded");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::CreateUnloadHandler()
{
    HILOGI("call!");
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = EventHandlerFactory::GetInstance().CreateEventHandler(UNLOAD_DP_SA_HANDLER);
    }
    if (unloadHandler_ == nullptr) {
        HILOGE("UnloadHandler is nullptr!");
        return DP_UNLOAD_HANDLER_NULLPTR;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::DestroyUnloadHandler()
{
    HILOGI("call!");
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        HILOGE("UnloadHandler is nullptr!");
        return DP_UNLOAD_HANDLER_NULLPTR;
    }
    unloadHandler_->RemoveTask(UNLOAD_TASK_ID);
    unloadHandler_ = nullptr;
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PutAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(PUT_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().PutAccessControlProfile(accessControlProfile);
}

int32_t DistributedDeviceProfileServiceNew::UpdateAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(UPDATE_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().UpdateAccessControlProfile(accessControlProfile);
}

int32_t DistributedDeviceProfileServiceNew::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_TRUST_DEVICE_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().GetTrustDeviceProfile(deviceId, trustDeviceProfile);
}

int32_t DistributedDeviceProfileServiceNew::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_TRUST_DEVICE_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().GetAllTrustDeviceProfile(trustDeviceProfiles);
}

int32_t DistributedDeviceProfileServiceNew::GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().GetAccessControlProfile(queryParams, accessControlProfiles);
}

int32_t DistributedDeviceProfileServiceNew::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().GetAllAccessControlProfile(accessControlProfiles);
}

int32_t DistributedDeviceProfileServiceNew::DeleteAccessControlProfile(int32_t accessControlId)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(DELETE_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return TrustProfileManager::GetInstance().DeleteAccessControlProfile(accessControlId);
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(PUT_SERVICE_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(PUT_SERVICE_PROFILE_BATCH)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(PUT_CHARACTERISTIC_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(PUT_CHARACTERISTIC_PROFILE_BATCH)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles);
}

int32_t DistributedDeviceProfileServiceNew::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(GET_DEVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
}

int32_t DistributedDeviceProfileServiceNew::GetServiceProfile(const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(GET_SERVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, serviceProfile);
}

int32_t DistributedDeviceProfileServiceNew::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(GET_CHARACTERISTIC_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName, characteristicKey,
        charProfile);
}

int32_t DistributedDeviceProfileServiceNew::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(DELETE_SERVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
}

int32_t DistributedDeviceProfileServiceNew::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(DELETE_CHARACTERISTIC_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey);
}

int32_t DistributedDeviceProfileServiceNew::SubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(SUBSCRIBE_DEVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(subscriberInfo);
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission(UNSUBSCRIBE_DEVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return SubscribeProfileManager::GetInstance().UnSubscribeDeviceProfile(subscriberInfo);
}

int32_t DistributedDeviceProfileServiceNew::SyncDeviceProfile(
    const DistributedDeviceProfile::DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerSyncPermission(SYNC_DEVICE_PROFILE)) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    return DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCompletedCallback);
}

int32_t DistributedDeviceProfileServiceNew::SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap)
{
    return SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(listenerMap);
}

int32_t DistributedDeviceProfileServiceNew::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    std::vector<std::string> argsInStr8;
    for (const auto& arg : args) {
        argsInStr8.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    DeviceProfileDumper::Dump(argsInStr8, result);

    if (!SaveStringToFd(fd, result)) {
        HILOGE("save to fd failed");
        return DP_INVALID_PARAMS;
    }
    return DP_SUCCESS;
}

void DistributedDeviceProfileServiceNew::DelayUnloadTask()
{
    HILOGI("delay unload task begin");
    if (!ProfileUtils::GetOnlineDevices().empty()) {
        HILOGI("already device online, not kill!");
        return;
    }
    auto task = []() {
        HILOGI("do unload task");
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("get samgr failed");
            return;
        }
        if (!ProfileUtils::GetOnlineDevices().empty()) {
            HILOGI("already device online in 3 min, not kill!");
            return;
        }
        int32_t unloadResult = samgrProxy->UnloadSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
        if (unloadResult != DP_SUCCESS) {
            HILOGE("remove system ability failed");
            return;
        }
        HILOGI("kill dp svr success!");
    };
    unloadHandler_->RemoveTask(UNLOAD_TASK_ID);
    HILOGI("delay unload task post task");
    unloadHandler_->PostTask(task, UNLOAD_TASK_ID, DELAY_TIME);
}

void DistributedDeviceProfileServiceNew::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    HILOGI("start reason %{public}s", startReason.GetName().c_str());
    if (!Init()) {
        HILOGE("init failed");
        return;
    }
    if (CreateUnloadHandler() == DP_SUCCESS) {
        HILOGI("CreateUnloadHandler success!");
        DelayUnloadTask();
    }
    if (!Publish(this)) {
        HILOGE("publish SA failed");
        return;
    }
}

void DistributedDeviceProfileServiceNew::OnStop()
{
    HILOGI("called");
    DestroyUnloadHandler();
    if (!UnInit()) {
        HILOGE("Uninit failed");
        return;
    }
}

int32_t DistributedDeviceProfileServiceNew::OnIdle(const SystemAbilityOnDemandReason& idleReason)
{
    HILOGI("idle reason %{public}d", idleReason.GetId());
    return UNLOAD_IMMEDIATELY;
}
} // namespace DeviceProfile
} // namespace OHOS