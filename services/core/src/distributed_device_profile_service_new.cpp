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

#include "common_event_support.h"
#include "content_sensor_manager.h"
#include "device_profile_dumper.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "dm_adapter.h"
#include "device_profile_manager.h"
#include "dp_radar_helper.h"
#include "event_handler_factory.h"
#include "multi_user_manager.h"
#include "permission_manager.h"
#include "profile_cache.h"
#include "static_profile_manager.h"
#include "static_capability_collector.h"
#include "subscribe_profile_manager.h"
#include "switch_profile_manager.h"
#include "trust_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileServiceNew";
const std::string UNLOAD_TASK_ID = "unload_dp_svr";
constexpr int32_t DELAY_TIME = 180000;
constexpr int32_t UNLOAD_IMMEDIATELY = 0;
constexpr int32_t WAIT_BUSINESS_PUT_TIME_S = 5;
constexpr int32_t WRTE_CACHE_PROFILE_DELAY_TIME_US = 200 * 1000;
constexpr int32_t WRTE_CACHE_PROFILE_RETRY_TIMES = 20;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileServiceNew);

DistributedDeviceProfileServiceNew::DistributedDeviceProfileServiceNew()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true)
{
    HILOGI("DPService construct!");
}

DistributedDeviceProfileServiceNew::~DistributedDeviceProfileServiceNew()
{
    HILOGI("DPService destruction!");
}

int32_t DistributedDeviceProfileServiceNew::Init()
{
    HILOGI("init begin");
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
    if (SubscribeProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("SubscribeProfileManager init failed");
        return DP_SUBSCRIBE_PROFILE_MANAGER_INIT_FAIL;
    }
    HILOGI("init finish");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::PostInit()
{
    HILOGI("PostInit begin");
    if (SwitchProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("SwitchProfileManager init failed");
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (DeviceProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("DeviceProfileManager init failed");
        return DP_DEVICE_PROFILE_MANAGER_INIT_FAIL;
    }
    if (StaticProfileManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("StaticProfileManager init failed");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (ProfileCache::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("ProfileCache init failed");
        return DP_CACHE_INIT_FAIL;
    }
    if (StaticCapabilityCollector::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("StaticCapabilityCollector init failed");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("ContentSensorManager init failed");
        return DP_CONTENT_SENSOR_MANAGER_INIT_FAIL;
    }
    if (MultiUserManager::GetInstance().Init() != DP_SUCCESS) {
        HILOGE("MultiUserManager init failed");
        return DP_MULTI_USER_MANAGER_INIT_FAIL;
    }
    SaveSwitchProfilesFromTempCache();
    SaveDynamicProfilesFromTempCache();
    isInited_ = true;
    HILOGI("PostInit finish");
    NotifyDeviceProfileInited();
    return DP_SUCCESS;
}

bool DistributedDeviceProfileServiceNew::IsInited()
{
    return isInited_;
}

int32_t DistributedDeviceProfileServiceNew::UnInit()
{
    isInited_ = false;
    if (TrustProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("TrustProfileManager UnInit failed");
        return DP_TRUST_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (SwitchProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("SwitchProfileManager UnInit failed");
        return DP_DEVICE_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (DeviceProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DeviceProfileManager UnInit failed");
        return DP_DEVICE_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (StaticProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("StaticProfileManager UnInit failed");
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (ProfileCache::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ProfileCache UnInit failed");
        return DP_CACHE_INIT_FAIL;
    }
    if (PermissionManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("DpDeviceManager UnInit failed");
        return DP_DEVICE_MANAGER_UNINIT_FAIL;
    }
    if (SubscribeProfileManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("SubscribeProfileManager UnInit failed");
        return DP_SUBSCRIBE_DEVICE_PROFILE_MANAGER_UNINIT_FAIL;
    }
    if (StaticCapabilityCollector::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("StaticCapabilityCollector UnInit failed");
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (ContentSensorManager::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("ContentSensorManager UnInit failed");
        return DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL;
    }
    if (EventHandlerFactory::GetInstance().UnInit() != DP_SUCCESS) {
        HILOGE("EventHandlerFactory UnInit failed");
        return DP_CACHE_UNINIT_FAIL;
    }
    DestroyUnloadHandler();
    ClearProfileCache();
    HILOGI("UnInit succeeded");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::CreateUnloadHandler()
{
    HILOGD("call!");
    std::lock_guard<std::mutex> lock(unloadMutex_);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = EventHandlerFactory::GetInstance().GetEventHandler();
    }
    if (unloadHandler_ == nullptr) {
        HILOGE("UnloadHandler is nullptr!");
        return DP_UNLOAD_HANDLER_NULLPTR;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::DestroyUnloadHandler()
{
    HILOGD("call!");
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
    int32_t ret = TrustProfileManager::GetInstance().PutAccessControlProfile(accessControlProfile);
    DpRadarHelper::GetInstance().ReportPutAclProfile(ret, accessControlProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::UpdateAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(UPDATE_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().UpdateAccessControlProfile(accessControlProfile);
    DpRadarHelper::GetInstance().ReportUpdateAclProfile(ret, accessControlProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_TRUST_DEVICE_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetTrustDeviceProfile(deviceId, trustDeviceProfile);
    DpRadarHelper::GetInstance().ReportGetTrustProfile(ret, deviceId, trustDeviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_TRUST_DEVICE_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAllTrustDeviceProfile(trustDeviceProfiles);
    DpRadarHelper::GetInstance().ReportGetAllTrustProfile(ret, trustDeviceProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAccessControlProfile(queryParams, accessControlProfiles);
    DpRadarHelper::GetInstance().ReportGetAclProfile(ret, accessControlProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(GET_ALL_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().GetAllAccessControlProfile(accessControlProfiles);
    DpRadarHelper::GetInstance().ReportGetAllAclProfile(ret, accessControlProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteAccessControlProfile(int32_t accessControlId)
{
    if (!PermissionManager::GetInstance().IsCallerTrust(DELETE_ACCESS_CONTROL_PROFILE)) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    int32_t ret = TrustProfileManager::GetInstance().DeleteAccessControlProfile(accessControlId);
    DpRadarHelper::GetInstance().ReportDeleteAclProfile(ret);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface PutServiceProfile");
    if (!IsInited()) {
        return AddSvrProfilesToCache({ serviceProfile });
    }
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    DpRadarHelper::GetInstance().ReportPutServiceProfile(ret, serviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface PutServiceProfileBatch");
    if (!IsInited()) {
        return AddSvrProfilesToCache(serviceProfiles);
    }
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
    DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(ret, serviceProfiles);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("the caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    if (!IsInited()) {
        return AddCharProfilesToCache({ charProfile });
    }
    if (charProfile.GetCharacteristicKey() == SWITCH_STATUS) {
        int32_t switchRet = SwitchProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
        DpRadarHelper::GetInstance().ReportPutCharProfile(switchRet, charProfile);
        return switchRet;
    }
    HILOGD("CheckCallerPermission success interface DeviceProfileManager::PutCharacteristicProfile");
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    DpRadarHelper::GetInstance().ReportPutCharProfile(ret, charProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    if (charProfiles.empty()) {
        HILOGE("charProfiles is empty");
        return DP_PUT_CHAR_BATCH_FAIL;
    }
    if (charProfiles.size() > MAX_CHAR_SIZE) {
        HILOGE("charProfiles size is too large");
        return DP_INVALID_PARAMS;
    }
    if (!IsInited()) {
        return AddCharProfilesToCache(charProfiles);
    }
    std::vector<CharacteristicProfile> switchCharProfiles;
    std::vector<CharacteristicProfile> dynamicCharProfiles;
    for (auto& profile : charProfiles) {
        if (profile.GetCharacteristicKey() == SWITCH_STATUS) {
            switchCharProfiles.push_back(profile);
            continue;
        }
        dynamicCharProfiles.push_back(profile);
    }
    int32_t switchRes = DP_SUCCESS;
    if (switchCharProfiles.size() > 0) {
        switchRes = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(switchCharProfiles);
        DpRadarHelper::GetInstance().ReportPutCharProfileBatch(switchRes, switchCharProfiles);
    }
    if (switchRes != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfileBatch fail, res:%{public}d", switchRes);
    }
    int32_t dynamicRes = DP_SUCCESS;
    if (dynamicCharProfiles.size() > 0) {
        dynamicRes = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(dynamicCharProfiles);
        DpRadarHelper::GetInstance().ReportPutCharProfileBatch(dynamicRes, dynamicCharProfiles);
    }
    if (dynamicRes != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfileBatch fail, res:%{public}d", dynamicRes);
    }
    if (switchRes != DP_SUCCESS || dynamicRes != DP_SUCCESS) {
        return DP_PUT_CHAR_BATCH_FAIL;
    }
    HILOGD("PutCharacteristicProfileBatch success ");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface GetDeviceProfile");
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
    DpRadarHelper::GetInstance().ReportGetDeviceProfile(ret, deviceId, deviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetServiceProfile(const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface GetServiceProfile");
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, serviceProfile);
    DpRadarHelper::GetInstance().ReportGetServiceProfile(ret, deviceId, serviceProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    if (characteristicKey == SWITCH_STATUS) {
        HILOGD("CheckCallerPermission success interface SwitchProfileManager::GetCharacteristicProfile");
        int32_t switchRet = SwitchProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
            characteristicKey, charProfile);
        DpRadarHelper::GetInstance().ReportGetCharProfile(switchRet, deviceId, charProfile);
        return switchRet;
    }
    if (characteristicKey == STATIC_CHARACTERISTIC_KEY) {
        HILOGD("CheckCallerPermission success interface StaticProfileManager::GetCharacteristicProfile");
        int32_t staticRet = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
            characteristicKey, charProfile);
        DpRadarHelper::GetInstance().ReportGetCharProfile(staticRet, deviceId, charProfile);
        return staticRet;
    }
    HILOGD("CheckCallerPermission success interface DeviceProfileManager::GetCharacteristicProfile");
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    DpRadarHelper::GetInstance().ReportGetCharProfile(ret, deviceId, charProfile);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface DeleteServiceProfile");
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    DpRadarHelper::GetInstance().ReportDeleteServiceProfile(ret, deviceId);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, bool isMultiUser, int32_t userId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface DeleteCharacteristicProfile");
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey, isMultiUser, userId);
    DpRadarHelper::GetInstance().ReportDeleteCharProfile(ret, deviceId);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface SubscribeDeviceProfile");
    int32_t ret = SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(subscriberInfo);
    DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(ret, subscriberInfo);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribeDeviceProfile(const SubscribeInfo& subscriberInfo)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerPermission success interface UnSubscribeDeviceProfile");
    int32_t ret = SubscribeProfileManager::GetInstance().UnSubscribeDeviceProfile(subscriberInfo);
    DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(ret, subscriberInfo);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SyncDeviceProfile(
    const DistributedDeviceProfile::DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerSyncPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    HILOGD("CheckCallerSyncPermission success interface SyncDeviceProfile");
    int32_t ret = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCompletedCallback);
    DpRadarHelper::GetInstance().ReportSyncDeviceProfile(ret);
    return ret;
}

int32_t DistributedDeviceProfileServiceNew::SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap)
{
    return SubscribeProfileManager::GetInstance().SubscribeDeviceProfile(listenerMap);
}

int32_t DistributedDeviceProfileServiceNew::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    if (args.size() > MAX_DUMP_ARGS_SIZE) {
        HILOGE("args size is too large");
        return DP_INVALID_PARAMS;
    }
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
    if (unloadHandler_ == nullptr) {
        return;
    }
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
    AddSystemAbilityListener(SOFTBUS_SERVER_SA_ID);
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    AddSystemAbilityListener(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (!Publish(this)) {
        HILOGE("publish SA failed");
        return;
    }
}

void DistributedDeviceProfileServiceNew::OnStop()
{
    HILOGI("called");
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

void DistributedDeviceProfileServiceNew::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("called systemAbilityId:%{public}d", systemAbilityId);
    if (DistributedDeviceProfile::DistributedDeviceProfileServiceNew::GetInstance().IsInited()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(depSaIdsMtx_);
        if (depSaIds_.empty()) {
            return;
        }
        depSaIds_.erase(systemAbilityId);
        if (!depSaIds_.empty()) {
            return;
        }
    }
    if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        SubscribeAccountCommonEvent();
    }
    PostInit();
}

void DistributedDeviceProfileServiceNew::SubscribeAccountCommonEvent()
{
    HILOGI("Start");
    if (accountCommonEventManager_ == nullptr) {
        accountCommonEventManager_ = std::make_shared<DpAccountCommonEventManager>();
    }
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        this->AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> AccountCommonEventVec;
    AccountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    AccountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    AccountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    AccountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    if (accountCommonEventManager_->SubscribeAccountCommonEvent(AccountCommonEventVec, callback)) {
        HILOGI("Success");
    }
    return;
}

void DistributedDeviceProfileServiceNew::AccountCommonEventCallback(int32_t userId, const std::string commonEventType)
{
    HILOGI("CommonEventType: %{public}s, userId: %{public}d", commonEventType.c_str(), userId);
    if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        // swithed
        MultiUserManager::GetInstance().SetCurrentForegroundUserID(userId);
    } else if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN) {
    } else if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT) {
    } else if (commonEventType == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
    } else {
        HILOGE("Invalied account common event.");
    }
    return;
}

int32_t DistributedDeviceProfileServiceNew::AddSvrProfilesToCache(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (serviceProfiles.empty()) {
        HILOGE("serviceProfiles empty");
        return DP_INVALID_PARAM;
    }
    HILOGI("serviceProfiles.size:%{public}zu", serviceProfiles.size());
    std::map<std::string, std::string> entries;
    for (const auto& item : serviceProfiles) {
        if (!ProfileUtils::IsSvrProfileValid(item)) {
            HILOGE("the is invalid, serviceProfile:%{public}s", item.dump().c_str());
            return DP_INVALID_PARAM;
        }
        if (ProfileCache::GetInstance().IsServiceProfileExist(item)) {
            HILOGW("the profile is exist!, serviceProfile:%{public}s", item.dump().c_str());
            return DP_CACHE_EXIST;
        }
        ProfileUtils::ServiceProfileToEntries(item, entries);
    }
    std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
    for (const auto& [key, value] : entries) {
        dynamicProfileMap_[key] = value;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::AddCharProfilesToCache(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    if (charProfiles.empty()) {
        HILOGE("charProfiles empty");
        return DP_INVALID_PARAM;
    }
    HILOGI("charProfiles.size:%{public}zu", charProfiles.size());
    std::vector<CharacteristicProfile> switchCharProfiles;
    std::map<std::string, std::string> entries;
    for (const auto& item : charProfiles) {
        if (!ProfileUtils::IsCharProfileValid(item)) {
            HILOGE("the is invalid, charProfile:%{public}s", item.dump().c_str());
            return DP_INVALID_PARAM;
        }
        if (ProfileCache::GetInstance().IsCharProfileExist(item)) {
            HILOGW("the profile is exist!, charProfile:%{public}s", item.dump().c_str());
            return DP_CACHE_EXIST;
        }
        if (item.GetCharacteristicKey() == SWITCH_STATUS) {
            switchCharProfiles.push_back(item);
            continue;
        }
        ProfileUtils::CharacteristicProfileToEntries(item, entries);
    }
    if (!entries.empty()) {
        HILOGI("entries.size:%{public}zu", entries.size());
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        for (const auto& [key, value] : entries) {
            dynamicProfileMap_[key] = value;
        }
    }
    if (!switchCharProfiles.empty()) {
        HILOGI("switchCharProfiles.size:%{public}zu", switchCharProfiles.size());
        std::lock_guard<std::mutex> lock(switchProfileMapMtx_);
        for (const auto& item : charProfiles) {
            std::string profileKey = ProfileUtils::GenerateCharProfileKey(item.GetDeviceId(),
                item.GetServiceName(), item.GetCharacteristicKey());
            switchProfileMap_[profileKey] = item;
        }
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::SaveSwitchProfilesFromTempCache()
{
    std::vector<CharacteristicProfile> switchCharProfiles;
    {
        std::lock_guard<std::mutex> lock(switchProfileMapMtx_);
        if (switchProfileMap_.empty()) {
            HILOGW("switchProfileMap empty");
            return DP_SUCCESS;
        }
        HILOGI("switchProfileMap.size:%{public}zu", switchProfileMap_.size());
        for (const auto& [profileKey, item] : switchProfileMap_) {
            switchCharProfiles.emplace_back(item);
        }
        switchProfileMap_.clear();
    }
    int32_t ret = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(switchCharProfiles);
    DpRadarHelper::GetInstance().ReportPutCharProfileBatch(ret, switchCharProfiles);
    if (ret != DP_SUCCESS) {
        HILOGE("PutCharacteristicProfileBatch fail, ret: %{public}d!", ret);
    }
    return ret;
}

void DistributedDeviceProfileServiceNew::GetDynamicProfilesFromTempCache(
    std::map<std::string, std::string>& entries)
{
    {
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        if (dynamicProfileMap_.empty()) {
            HILOGW("dynamicProfileMap empty!");
            return;
        }
        for (const auto& [key, value] : dynamicProfileMap_) {
            entries[key] = value;
        }
    }
}

int32_t DistributedDeviceProfileServiceNew::SaveDynamicProfilesFromTempCache()
{
    std::map<std::string, std::string> entries;
    GetDynamicProfilesFromTempCache(entries);
    if (entries.empty() && DeviceProfileManager::GetInstance().IsFirstInitDB()) {
        HILOGW("entries empty!");
        sleep(WAIT_BUSINESS_PUT_TIME_S);
        GetDynamicProfilesFromTempCache(entries);
    }
    HILOGI("entries.size:%{public}zu", entries.size());
    int32_t tryTimes = WRTE_CACHE_PROFILE_RETRY_TIMES;
    while (tryTimes > 0) {
        if (DeviceProfileManager::GetInstance().SavePutTempCache(entries) == DP_SUCCESS) {
            break;
        }
        HILOGW("SavePutTempCache fail! leftTimes:%{public}d", tryTimes);
        usleep(WRTE_CACHE_PROFILE_DELAY_TIME_US);
        tryTimes--;
    }
    if (tryTimes <= 0) {
        DeviceProfileManager::GetInstance().ResetFirst();
    }
    {
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        dynamicProfileMap_.clear();
    }
    return DP_SUCCESS;
}

void DistributedDeviceProfileServiceNew::ClearProfileCache()
{
    {
        std::lock_guard<std::mutex> lock(dynamicProfileMapMtx_);
        dynamicProfileMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(switchProfileMapMtx_);
        switchProfileMap_.clear();
    }
}

int32_t DistributedDeviceProfileServiceNew::SubscribeDeviceProfileInited(int32_t saId,
    sptr <IRemoteObject> dpInitedCallback)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    if (dpInitedCallback == nullptr) {
        HILOGE("dpInitedCallback is nullptr");
        return DP_INVALID_PARAM;
    }
    if (saId <= 0 || saId > MAX_SAID) {
        HILOGE("saId is invalid, saId:%{public}d", saId);
        return DP_INVALID_PARAM;
    }
    if (isInited_.load()) {
        HILOGI("deviceProfile service is already inited.");
        sptr<IDpInitedCallback> callbackProxy = iface_cast<IDpInitedCallback>(dpInitedCallback);
        if (callbackProxy == nullptr) {
            HILOGE("Cast to IDpInitedCallback failed!");
            return DP_NULLPTR;
        }
        callbackProxy->OnDpInited();
    }
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    dpInitedCallbackMap_[saId] = dpInitedCallback;
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::UnSubscribeDeviceProfileInited(int32_t saId)
{
    if (!PermissionManager::GetInstance().CheckCallerPermission()) {
        HILOGE("this caller is permission denied!");
        return DP_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    dpInitedCallbackMap_.erase(saId);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileServiceNew::NotifyDeviceProfileInited()
{
    std::lock_guard<std::mutex> lock(dpInitedCallbackMapMtx_);
    for (const auto& [saId, callback] : dpInitedCallbackMap_) {
        sptr<IDpInitedCallback> callbackProxy = iface_cast<IDpInitedCallback>(callback);
        if (callbackProxy == nullptr) {
            HILOGE("Cast to IDpInitedCallback failed!");
            continue;
        }
        callbackProxy->OnDpInited();
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
