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

#include "distributed_device_profile_service.h"

#include "file_ex.h"
#include "string_ex.h"

#include "authority_manager.h"
#include "content_sensor_manager.h"
#include "device_profile_dumper.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "distributed_device_profile_service_new.h"
#include "dp_device_manager.h"
#include "dp_radar_helper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iprofile_event_notifier.h"
#include "iservice_registry.h"
#include "sa_profiles.h"
#include "service_characteristic_profile.h"
#include "sync_coordinator.h"
#include "system_ability_definition.h"
#include "subscribe_manager.h"
#include "trust_group_manager.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileService";
const std::string DP_DEVICE_SUB_TRACE = "DP_DEVICE_SUB";
const std::string TASK_ID = "unload";
const std::string BOOT_COMPLETED_EVENT = "usual.event.BOOT_COMPLETED";
const std::string STRING_DEVICE_ONLINE = "deviceonline";
const std::string EVENT_ID = "eventId";
const std::string NAME = "name";
const std::string INIT_TASK_ID = "CheckAndInitDP";
constexpr int32_t DELAY_TIME = 180000;
constexpr int32_t UNLOAD_IMMEDIATELY = 0;
constexpr int32_t INIT_BUSINESS_DELAY_TIME_US = 100 * 1000;
constexpr int32_t MAX_INIT_RETRY_TIMES = 1200;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileService);
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&DistributedDeviceProfileService::GetInstance());

DistributedDeviceProfileService::DistributedDeviceProfileService()
    : SystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, true)
{
}

bool DistributedDeviceProfileService::Init()
{
    HILOGI("called");
    {
        std::lock_guard<std::mutex> lock(unloadMutex_);
        auto runner = AppExecFwk::EventRunner::Create("unloadRunner");
        if (unloadHandler_ == nullptr) {
            unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        }
        if (unloadHandler_ == nullptr) {
            return false;
        }
    }
    HILOGI("init DistributedDeviceProfileServiceNew");
    DistributedDeviceProfile::DistributedDeviceProfileServiceNew::GetInstance().Init();
    auto executeInnerFunc = [this] {
        int32_t tryTimes = MAX_INIT_RETRY_TIMES;
        while (tryTimes > 0) {
            if (DoInit()) {
                break;
            }
            usleep(INIT_BUSINESS_DELAY_TIME_US);
            tryTimes--;
        }
        if (tryTimes <= 0) {
            DelayUnloadTask();
        }
    };
    unloadHandler_->PostTask(executeInnerFunc, INIT_TASK_ID, 0);
    HILOGI("init succeeded");
    return true;
}

int32_t DistributedDeviceProfileService::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    bool ret = AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        profile.GetServiceId());
    struct RadarInfo info = {
        .funcName = "PutDeviceProfile",
        .stageRes = ret ?
            static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
        .errCode = ERR_DP_PERMISSION_DENIED,
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    if (!ret) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
}

void DistributedDeviceProfileService::DeviceOnline()
{
    HILOGI("device online begin");
    isOnline_ = true;
    unloadHandler_->RemoveTask(TASK_ID);
}

int32_t DistributedDeviceProfileService::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    bool ret = AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_R,
        serviceId);
    struct RadarInfo info = {
        .funcName = "GetDeviceProfile",
        .stageRes = ret ?
            static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
        .errCode = ERR_DP_PERMISSION_DENIED,
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    if (!ret) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().GetDeviceProfile(udid, serviceId, profile);
}

int32_t DistributedDeviceProfileService::DeleteDeviceProfile(const std::string& serviceId)
{
    bool ret = AuthorityManager::GetInstance().CheckServiceAuthority(AuthValue::AUTH_W,
        serviceId);
    struct RadarInfo info = {
        .funcName = "DeleteDeviceProfile",
        .stageRes = ret ?
            static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
        .errCode = ERR_DP_PERMISSION_DENIED,
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    if (!ret) {
        return ERR_DP_PERMISSION_DENIED;
    }
    return DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile(serviceId);
}

int32_t DistributedDeviceProfileService::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    HITRACE_METER_NAME(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_SUB_TRACE);
    struct RadarInfo info = {
        .funcName = "SubscribeProfileEvents",
        .stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    return SubscribeManager::GetInstance().SubscribeProfileEvents(subscribeInfos,
        profileEventNotifier, failedEvents);
}

int32_t DistributedDeviceProfileService::UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    struct RadarInfo info = {
        .funcName = "UnsubscribeProfileEvents",
        .stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    return SubscribeManager::GetInstance().UnsubscribeProfileEvents(profileEvents,
        profileEventNotifier, failedEvents);
}

int32_t DistributedDeviceProfileService::SyncDeviceProfile(const SyncOptions& syncOptions,
    const sptr<IRemoteObject>& profileEventNotifier)
{
    bool ret = AuthorityManager::GetInstance().CheckInterfaceAuthority("sync");
    struct RadarInfo info = {
        .funcName = "SyncDeviceProfile",
        .stageRes = ret ?
            static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL),
        .bizState = static_cast<int32_t>(BizState::BIZ_STATE_END),
        .errCode = ERR_DP_PERMISSION_DENIED,
    };
    if (!DpRadarHelper::GetInstance().ReportSaCheckAuth(info)) {
        HILOGE("ReportSaCheckAuth failed");
    }
    if (!ret) {
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

void DistributedDeviceProfileService::DelayUnloadTask()
{
    HILOGI("delay unload task begin");
    auto task = [this]() {
        HILOGI("do unload task");
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            HILOGE("get samgr failed");
            return;
        }
        int32_t ret = samgrProxy->UnloadSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
        if (ret != ERR_OK) {
            HILOGE("remove system ability failed");
            return;
        }
    };
    unloadHandler_->RemoveTask(TASK_ID);
    if (!isOnline_) {
        HILOGI("delay unload task post task");
        unloadHandler_->PostTask(task, TASK_ID, DELAY_TIME);
    }
}

void DistributedDeviceProfileService::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    HILOGI("called");
    if (!Init()) {
        HILOGE("init failed");
    }
    if (!Publish(this)) {
        HILOGE("publish SA failed");
        return;
    }
    HILOGI("start reason %{public}s", startReason.GetName().c_str());
    DelayUnloadTask();
}

int32_t DistributedDeviceProfileService::OnIdle(const SystemAbilityOnDemandReason& idleReason)
{
    HILOGI("idle reason %{public}d", idleReason.GetId());
    return UNLOAD_IMMEDIATELY;
}

void DistributedDeviceProfileService::OnStop()
{
    HILOGI("called");
    if (!DistributedDeviceProfile::DistributedDeviceProfileServiceNew::GetInstance().UnInit()) {
        HILOGE("UnInit failed");
        return;
    }
}

bool DistributedDeviceProfileService::DoInit()
{
    HILOGI("called");
    if (!IsDepSAStart()) {
        HILOGE("Depend sa not start");
        return false;
    }
    if (!DoBusinessInit()) {
        HILOGE("DoBusinessInit init failed");
        return false;
    }
    HILOGI("DoInit succeeded");
    return true;
}

bool DistributedDeviceProfileService::IsDepSAStart()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        HILOGE("Get System Ability Manager failed");
        return false;
    }
    HILOGI("Check DSoftbus sa");
    auto remoteObject = saMgr->CheckSystemAbility(SOFTBUS_SERVER_SA_ID);
    if (remoteObject == nullptr) {
        HILOGE("DSoftbus not start");
        return false;
    }
    HILOGI("Check KVDB sa");
    remoteObject = saMgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (remoteObject == nullptr) {
        HILOGE("KVDB not start");
        return false;
    }
    HILOGI("Check DM sa");
    remoteObject = saMgr->CheckSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
    if (remoteObject == nullptr) {
        HILOGE("DM not start");
        return false;
    }
    return true;
}

bool DistributedDeviceProfileService::DoBusinessInit()
{
    HILOGI("called");
    if (!DpDeviceManager::GetInstance().Init()) {
        HILOGE("DeviceManager init failed");
        return false;
    }
    if (!AuthorityManager::GetInstance().Init()) {
        HILOGE("AuthorityManager init failed");
        return false;
    }
    if (DistributedDeviceProfile::DistributedDeviceProfileServiceNew::GetInstance().PostInit() != ERR_OK) {
        HILOGE("PostInit failed");
        return false;
    }
    HILOGI("DoBusinessInit succeeded");
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS
