/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <bitset>
#include <chrono>
#include <functional>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <profile_utils.h>
#include "profile_change_listener_stub.h"
#include "device_profile_load_callback.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_radar_helper.h"
#include "event_handler.h"
#include "event_runner.h"
#include "i_distributed_device_profile.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std::chrono_literals;

namespace {
    const std::string TAG = "Client";
    constexpr int32_t LOAD_SA_TIMEOUT_MS = 10000;
    constexpr int32_t MAX_RETRY_TIMES = 7;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileClient);

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::LoadDeviceProfileService()
{
    sptr<DeviceProfileLoadCallback> loadCallback = new DeviceProfileLoadCallback();
    if (loadCallback == nullptr) {
        HILOGE("loadCallback is nullptr.");
        return nullptr;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return nullptr;
    }

    int32_t ret = samgrProxy->LoadSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, loadCallback);
    int32_t stageRes = (ret == ERR_OK) ?
        static_cast<int32_t>(StageRes::STAGE_IDLE) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportLoadDpSa(stageRes);
    if (ret != ERR_OK) {
        HILOGE("Failed to Load systemAbility");
        return nullptr;
    }
    {
        std::unique_lock<std::mutex> lock(serviceLock_);
        auto waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
            [this]() { return dpProxy_ != nullptr; });
        if (waitStatus && dpProxy_ != nullptr) {
            HILOGE("Get profile Service success!");
            return dpProxy_;
        }
    }
    return nullptr;
}

void DistributedDeviceProfileClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    HILOGI("FinishStartSA");
    int32_t stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportLoadDpSaCb(stageRes);
    std::lock_guard<std::mutex> lock(serviceLock_);
    if (dpDeathRecipient_ == nullptr) {
        dpDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new DeviceProfileDeathRecipient);
    }
    if (remoteObject != nullptr) {
        remoteObject->AddDeathRecipient(dpDeathRecipient_);
        dpProxy_ = iface_cast<IDistributedDeviceProfile>(remoteObject);
        proxyConVar_.notify_one();
        DpRadarHelper::GetInstance().SetDeviceProfileInit(true);
    }
}

void DistributedDeviceProfileClient::LoadSystemAbilityFail()
{
    int32_t stageRes = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportLoadDpSaCb(stageRes);
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
}

void DistributedDeviceProfileClient::SendSubscribeInfosToService()
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("dpService is nullptr!");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(subscribeLock_);
        if (subscribeInfos_.empty() || subscribeInfos_.size() > MAX_SUBSCRIBE_INFO_SIZE) {
            HILOGE("SubscribeInfos size is invalid!size: %{public}zu!", subscribeInfos_.size());
            return;
        }
        dpService->SendSubscribeInfos(subscribeInfos_);
    }
}

int32_t DistributedDeviceProfileClient::PutAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->PutAccessControlProfile(accessControlProfile);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::PutAccessControlProfile, accessControlProfile);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::UpdateAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->UpdateAccessControlProfile(accessControlProfile);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::UpdateAccessControlProfile, accessControlProfile);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->GetTrustDeviceProfile(deviceId, trustDeviceProfile);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetTrustDeviceProfile, deviceId, trustDeviceProfile);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->GetAllTrustDeviceProfile(trustDeviceProfiles);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetAllTrustDeviceProfile, trustDeviceProfiles);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetAccessControlProfile(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (params.empty() || params.size() > MAX_PARAM_SIZE) {
        HILOGE("Params size is invalid! size: %{public}zu!", params.size());
        return DP_INVALID_PARAMS;
    }
    int32_t ret = dpService->GetAccessControlProfile(params, accessControlProfiles);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetAccessControlProfile, params,
            accessControlProfiles);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->GetAllAccessControlProfile(accessControlProfiles);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetAllAccessControlProfile, accessControlProfiles);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetAllAclIncludeLnnAcl(std::vector<AccessControlProfile>& accessControlProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->GetAllAclIncludeLnnAcl(accessControlProfiles);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetAllAclIncludeLnnAcl, accessControlProfiles);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::DeleteAccessControlProfile(int32_t accessControlId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->DeleteAccessControlProfile(accessControlId);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::DeleteAccessControlProfile, accessControlId);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutDeviceProfileBatch(deviceProfiles);
}

int32_t DistributedDeviceProfileClient::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->DeleteDeviceProfileBatch(deviceProfiles);
}

int32_t DistributedDeviceProfileClient::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutServiceProfile(serviceProfile);
}

//delete start
int32_t DistributedDeviceProfileClient::UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->UpdateServiceInfoProfile(serviceInfoProfile);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
    ServiceInfoProfile& serviceInfoProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileByUniqueKey(key, serviceInfoProfile);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileListByTokenId(key, serviceInfoProfiles);
}

int32_t DistributedDeviceProfileClient::GetAllServiceInfoProfileList(
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetAllServiceInfoProfileList(serviceInfoProfiles);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileListByBundleName(key, serviceInfoProfiles);
}
//delete end

int32_t DistributedDeviceProfileClient::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (serviceProfiles.empty() || serviceProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("ServiceProfiles size is invalid!size: %{public}zu!", serviceProfiles.size());
        return DP_INVALID_PARAMS;
    }
    return dpService->PutServiceProfileBatch(serviceProfiles);
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfile(const CharacteristicProfile& characteristicProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutCharacteristicProfile(characteristicProfile);
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (characteristicProfiles.empty()  || characteristicProfiles.size() > MAX_PROFILE_SIZE) {
        HILOGE("ServiceProfiles size is invalid!size: %{public}zu!", characteristicProfiles.size());
        return DP_INVALID_PARAMS;
    }
    return dpService->PutCharacteristicProfileBatch(characteristicProfiles);
}

int32_t DistributedDeviceProfileClient::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetDeviceProfile(deviceId, deviceProfile);
}

int32_t DistributedDeviceProfileClient::GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetDeviceProfiles(options, deviceProfiles);
}

int32_t DistributedDeviceProfileClient::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceProfile(deviceId, serviceName, serviceProfile);
}


int32_t DistributedDeviceProfileClient::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutProductInfoBatch(productInfos);
}

int32_t DistributedDeviceProfileClient::PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutDeviceIconInfoBatch(deviceIconInfos);
}

int32_t DistributedDeviceProfileClient::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetDeviceIconInfos(filterOptions, deviceIconInfos);
}

int32_t DistributedDeviceProfileClient::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, CharacteristicProfile& characteristicProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetCharacteristicProfile(deviceId, serviceName, characteristicId, characteristicProfile);
}

int32_t DistributedDeviceProfileClient::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
}

int32_t DistributedDeviceProfileClient::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, bool isMultiUser, int32_t userId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey, isMultiUser, userId);
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(subscribeLock_);
        if (subscribeInfos_.size() > MAX_LISTENER_SIZE) {
            HILOGE("ProfileChangeListeners size is invalid!size: %{public}zu!", subscribeInfos_.size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }
        std::string subscribeTag =
            subscribeInfo.GetSubscribeKey() + SEPARATOR + std::to_string(subscribeInfo.GetSaId());
        subscribeInfos_[subscribeTag] = subscribeInfo;
        HILOGI("subscribeInfos_.size is %{public}zu", subscribeInfos_.size());
    }
    return dpService->SubscribeDeviceProfile(subscribeInfo);
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(subscribeLock_);
        subscribeInfos_.erase(subscribeInfo.GetSubscribeKey() + SEPARATOR + std::to_string(subscribeInfo.GetSaId()));
        HILOGI("subscribeInfos_.size is %{public}zu", subscribeInfos_.size());
    }
    return dpService->UnSubscribeDeviceProfile(subscribeInfo);
}

int32_t DistributedDeviceProfileClient::SyncDeviceProfile(const DpSyncOptions& syncOptions,
    sptr<ISyncCompletedCallback> syncCb)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (syncCb == nullptr) {
        HILOGE("SyncCb is nullptr!");
        return DP_SYNC_DEVICE_FAIL;
    }
    sptr<IRemoteObject> syncCompletedCallback = syncCb->AsObject();
    if (syncCompletedCallback == nullptr) {
        HILOGE("SyncCb ipc cast fail!");
        return DP_SYNC_DEVICE_FAIL;
    }
    return dpService->SyncDeviceProfile(syncOptions, syncCompletedCallback);
}

int32_t DistributedDeviceProfileClient::SyncStaticProfile(const DpSyncOptions& syncOptions,
    sptr<ISyncCompletedCallback> syncCb)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (syncCb == nullptr) {
        HILOGE("SyncCb is nullptr!");
        return DP_SYNC_DEVICE_FAIL;
    }
    sptr<IRemoteObject> syncCompletedCallback = syncCb->AsObject();
    if (syncCompletedCallback == nullptr) {
        HILOGE("SyncCb ipc cast fail!");
        return DP_SYNC_DEVICE_FAIL;
    }
    return dpService->SyncStaticProfile(syncOptions, syncCompletedCallback);
}

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::GetDeviceProfileService()
{
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
        auto object = samgrProxy->CheckSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
        int32_t stageRes = (object != nullptr) ?
                static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
        if (!DpRadarHelper::GetInstance().IsDeviceProfileInit()) {
            DpRadarHelper::GetInstance().ReportCheckDpSa(stageRes);
        }
        if (object != nullptr) {
            HILOGD("get service succeeded");
            if (dpDeathRecipient_ == nullptr) {
                dpDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new DeviceProfileDeathRecipient);
            }
            object->AddDeathRecipient(dpDeathRecipient_);
            dpProxy_ = iface_cast<IDistributedDeviceProfile>(object);
            return dpProxy_;
        }
    }

    HILOGW("remoteObject is null!");
    if (LoadDeviceProfileService()) {
        std::lock_guard<std::mutex> lock(serviceLock_);
        if (dpProxy_ != nullptr) {
            return dpProxy_;
        } else {
            HILOGE("load dp service failed");
            return nullptr;
        }
    }
    HILOGE("load dp service failed");
    return nullptr;
}

void DistributedDeviceProfileClient::OnServiceDied(const sptr<IRemoteObject>& remote)
{
    HILOGI("called");
    DpRadarHelper::GetInstance().SetDeviceProfileInit(false);
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
}

void DistributedDeviceProfileClient::DeviceProfileDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    HILOGI("call!");
    DistributedDeviceProfileClient::GetInstance().OnServiceDied(remote.promote());
}

void DistributedDeviceProfileClient::SubscribeDeviceProfileSA()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return;
    }
    int32_t ret = DP_SUCCESS;
    {
        std::lock_guard<std::mutex> lock(saListenerLock_);
        if (saListenerCallback_ == nullptr) {
            saListenerCallback_ = sptr<SystemAbilityListener>(new SystemAbilityListener());
        }
        if (saListenerCallback_ == nullptr) {
            HILOGE("Create saListenerCallback failed!");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, saListenerCallback_);
    }
    if (ret != DP_SUCCESS) {
        HILOGE("subscribe dp sa failed! ret %{public}d.", ret);
        return;
    }
    HILOGD("subscribe dp sa success");
}

void DistributedDeviceProfileClient::StartThreadSendSubscribeInfos()
{
    HILOGI("Send SubscribeInfos cache in proxy to service!");
    std::thread(&DistributedDeviceProfileClient::SendSubscribeInfosToService, this).detach();
}

void DistributedDeviceProfileClient::ReSubscribeDeviceProfileInited()
{
    int32_t saId = 0;
    sptr<IDpInitedCallback> dpInitedCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(dpInitedLock_);
        if (dpInitedCallback_ == nullptr) {
            HILOGI("not use Retry subscribe dp inited");
            return;
        }
        saId = saId_;
        dpInitedCallback = dpInitedCallback_;
    }
    auto autoTask = [this, saId, dpInitedCallback] () {
        int32_t ret = SubscribeDeviceProfileInited(saId, dpInitedCallback);
        if (ret != DP_SUCCESS) {
            HILOGE("Retry subscribe dp inited failed");
        } else {
            HILOGD("Retry subscribe dp inited succeed");
        }
    };
    std::thread(autoTask).detach();
}

void DistributedDeviceProfileClient::ReSubscribePinCodeInvalid()
{
    HILOGI("call");
    std::string bundleName = "";
    int32_t pinExchangeType = DEFAULT_PIN_EXCHANGE_TYPE;
    sptr<IPincodeInvalidCallback> pinCodeCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(pinCodeLock_);
        if (pinCodeCallback_ == nullptr) {
            HILOGI("not use Retry subscribe pincode invalid");
            return;
        }
        bundleName = bundleName_;
        pinExchangeType = pinExchangeType_;
        pinCodeCallback = pinCodeCallback_;
    }
    int32_t ret = SubscribePinCodeInvalid(bundleName, pinExchangeType, pinCodeCallback);
    if (ret != DP_SUCCESS) {
        HILOGE("Retry subscribe pincode invalid failed");
    } else {
        HILOGI("Retry subscribe pincode invalid succeed");
    }
}

void DistributedDeviceProfileClient::StartThreadReSubscribePinCodeInvalid()
{
    HILOGI("Send Subscribe pincode invalid cache in proxy to service!");
    std::thread(&DistributedDeviceProfileClient::ReSubscribePinCodeInvalid, this).detach();
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfileInited(int32_t saId,
    sptr<IDpInitedCallback> initedCb)
{
    HILOGI("enter, saId:%{public}d", saId);
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_SUBSCRIBE_INITED_FALI;
    }
    if (saId <= 0 || saId > MAX_SAID) {
        HILOGE("saId is invalid, saId:%{public}d", saId);
        return DP_INVALID_PARAM;
    }
    if (initedCb == nullptr) {
        HILOGE("initedCb is nullptr!");
        return DP_INVALID_PARAM;
    }
    sptr<IRemoteObject> dpInitedCallback = initedCb->AsObject();
    if (dpInitedCallback == nullptr) {
        HILOGE("SyncCb ipc cast fail!");
        return DP_SUBSCRIBE_INITED_FALI;
    }
    {
        std::lock_guard<std::mutex> lock(dpInitedLock_);
        int32_t ret = dpService->SubscribeDeviceProfileInited(saId, dpInitedCallback);
        if (ret != DP_SUCCESS) {
            HILOGE("Subscribe DP Inited failed!");
            return ret;
        }
        saId_ = saId;
        dpInitedCallback_ = initedCb;
    }
    HILOGD("Subscribe DP Inited succeed!");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfileInited(int32_t saId)
{
    HILOGI("enter");
    {
        std::lock_guard<std::mutex> lock(dpInitedLock_);
        if (dpInitedCallback_ == nullptr) {
            HILOGE("not subscribe dp inited, no need unsubscribe dp inited");
            return DP_SUCCESS;
        }
    }
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (saId <= 0 || saId > MAX_SAID) {
        HILOGE("saId is invalid, saId:%{public}d", saId);
        return DP_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(dpInitedLock_);
        int32_t ret = dpService->UnSubscribeDeviceProfileInited(saId);
        if (ret != DP_SUCCESS) {
            HILOGE("Unsubscribe DP Inited failed!");
            return ret;
        }
        dpInitedCallback_ = nullptr;
    }
    HILOGD("Unsubscribe DP Inited succeed!");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::SubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType,
    sptr<IPincodeInvalidCallback> pinCodeCallback)
{
    HILOGI("enter");
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_SUBSCRIBE_INITED_FALI;
    }
    if (bundleName.empty()) {
        HILOGE("tokenId is invalid");
        return DP_INVALID_PARAM;
    }
    if (pinExchangeType == DEFAULT_PIN_EXCHANGE_TYPE) {
        HILOGE("pinExchangeType is invalid");
        return DP_INVALID_PARAM;
    }
    if (pinCodeCallback == nullptr) {
        HILOGE("pinCodeCallback is nullptr!");
        return DP_INVALID_PARAM;
    }
    sptr<IRemoteObject> innerPinCodeCallback = pinCodeCallback->AsObject();
    if (innerPinCodeCallback == nullptr) {
        HILOGE("pinCodeCallback ipc cast fail!");
        return DP_SUBSCRIBE_PINCODE_INVALID;
    }
    {
        std::lock_guard<std::mutex> lock(pinCodeLock_);
        int32_t ret = dpService->SubscribePinCodeInvalid(bundleName, pinExchangeType, innerPinCodeCallback);
        if (ret != DP_SUCCESS) {
            HILOGE("Subscribe DP Inited failed!");
            return ret;
        }
        bundleName_ = bundleName;
        pinExchangeType_ = pinExchangeType;
        pinCodeCallback_ = pinCodeCallback;
    }
    HILOGI("Subscribe pincodeInvalid succeed!");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::UnSubscribePinCodeInvalid(const std::string& bundleName,
    int32_t pinExchangeType)
{
    HILOGI("enter");
    {
        std::lock_guard<std::mutex> lock(pinCodeLock_);
        if (pinCodeCallback_ == nullptr) {
            HILOGE("not subscribe pincode invalid, no need unsubscribe pincode invalid");
            return DP_SUCCESS;
        }
    }
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (bundleName.empty()) {
        HILOGE("tokenId is invalid");
        return DP_INVALID_PARAM;
    }
    if (pinExchangeType == DEFAULT_PIN_EXCHANGE_TYPE) {
        HILOGE("pinExchangeType is invalid");
        return DP_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(pinCodeLock_);
        int32_t ret = dpService->UnSubscribePinCodeInvalid(bundleName, pinExchangeType);
        if (ret != DP_SUCCESS) {
            HILOGE("Unsubscribe DP Inited failed!");
            return ret;
        }
        pinCodeCallback_ = nullptr;
    }
    HILOGD("Unsubscribe pincode invalid succeed!");
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::PutAllTrustedDevices(const std::vector<TrustedDeviceInfo>& deviceInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (deviceInfos.empty() || deviceInfos.size() > MAX_TRUSTED_DEVICE_SIZE) {
        HILOGE("size is invalid! size: %{public}zu!", deviceInfos.size());
        return DP_INVALID_PARAMS;
    }
    int32_t ret = dpService->PutAllTrustedDevices(deviceInfos);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::PutAllTrustedDevices, deviceInfos);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::PutSessionKey(
    uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->PutSessionKey(userId, sessionKey, sessionKeyId);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::PutSessionKey, userId, sessionKey, sessionKeyId);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetSessionKey(
    uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetSessionKey(userId, sessionKeyId, sessionKey);
}

int32_t DistributedDeviceProfileClient::UpdateSessionKey(
    uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->UpdateSessionKey(userId, sessionKeyId, sessionKey);
}

int32_t DistributedDeviceProfileClient::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->DeleteSessionKey(userId, sessionKeyId);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::DeleteSessionKey, userId, sessionKeyId);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->PutLocalServiceInfo(localServiceInfo);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::PutLocalServiceInfo, localServiceInfo);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->UpdateLocalServiceInfo(localServiceInfo);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::UpdateLocalServiceInfo, localServiceInfo);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
    int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, localServiceInfo);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::GetLocalServiceInfoByBundleAndPinType, bundleName,
            pinExchangeType, localServiceInfo);
    }
    return ret;
}

int32_t DistributedDeviceProfileClient::DeleteLocalServiceInfo(const std::string& bundleName,
    int32_t pinExchangeType)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    int32_t ret = dpService->DeleteLocalServiceInfo(bundleName, pinExchangeType);
    if (retryErrCodes_.count(ret) != 0) {
        ret = RetryClientRequest(ret, &IDistributedDeviceProfile::DeleteLocalServiceInfo, bundleName, pinExchangeType);
    }
    return ret;
}

void DistributedDeviceProfileClient::SystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    HILOGD("dp sa removed");
}

void DistributedDeviceProfileClient::SystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    HILOGI("dp sa started");
    DistributedDeviceProfileClient::GetInstance().StartThreadSendSubscribeInfos();
    DistributedDeviceProfileClient::GetInstance().StartThreadReSubscribePinCodeInvalid();
    DistributedDeviceProfileClient::GetInstance().ReSubscribeDeviceProfileInited();
    DistributedDeviceProfileClient::GetInstance().StartThreadReRegisterBusinessCallback();
}

void DistributedDeviceProfileClient::ReleaseSubscribeDeviceProfileSA()
{
    std::lock_guard<std::mutex> lock(saListenerLock_);
    if (saListenerCallback_ == nullptr) {
        return;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        saListenerCallback_ = nullptr;
        return;
    }

    int32_t ret = samgrProxy->UnSubscribeSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID, saListenerCallback_);
    if (ret != DP_SUCCESS) {
        HILOGE("unsubscribe dp sa failed, ret=%{public}d", ret);
        return;
    }

    HILOGD("unsubscribe dp sa success");
}

void DistributedDeviceProfileClient::ReleaseSubscribeDeviceProfileInited()
{
    int32_t saId = 0;
    {
        std::lock_guard<std::mutex> lock(dpInitedLock_);
        if (dpInitedCallback_ == nullptr) {
            return;
        }
        saId = saId_;
    }

    int32_t ret = UnSubscribeDeviceProfileInited(saId);
    if (ret != DP_SUCCESS) {
        HILOGE("unsubscribe device profile inited failed, ret=%{public}d", ret);
        return;
    }

    HILOGD("unsubscribe device profile inited success");
}

void DistributedDeviceProfileClient::ReleaseSubscribePinCodeInvalid()
{
    std::string bundleName = "";
    int32_t pinExchangeType = DEFAULT_PIN_EXCHANGE_TYPE;
    {
        std::lock_guard<std::mutex> lock(pinCodeLock_);
        if (pinCodeCallback_ == nullptr) {
            return;
        }
        bundleName = bundleName_;
        pinExchangeType = pinExchangeType_;
    }

    int32_t ret = UnSubscribePinCodeInvalid(bundleName, pinExchangeType);
    if (ret != DP_SUCCESS) {
        HILOGE("unscribe pincode invalid failed, ret=%{public}d", ret);
        return;
    }

    HILOGD("unscribe pincode invalid success");
}

void DistributedDeviceProfileClient::ReleaseDeathRecipient()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    if (dpProxy_ != nullptr && dpProxy_->AsObject() != nullptr && dpDeathRecipient_ != nullptr) {
        dpProxy_->AsObject()->RemoveDeathRecipient(dpDeathRecipient_);
    }
    dpDeathRecipient_ = nullptr;
    dpProxy_ = nullptr;
}

template <typename Method, typename... Args>
int32_t DistributedDeviceProfileClient::RetryClientRequest(int32_t firesRet, Method method, Args&& ... args)
{
    int32_t ret = firesRet;
    int32_t delays[MAX_RETRY_TIMES] = {US_100000, US_200000, US_300000, US_400000, US_500000, US_500000, US_500000};
    for (int32_t i = 0; i < MAX_RETRY_TIMES; ++i) {
        HILOGI("retry times:%{public}d, retry reason:%{public}d", i + 1, ret);
        usleep(delays[i]);
        auto dpService = GetDeviceProfileService();
        if (dpService == nullptr) {
            HILOGE("get dp service failed");
            return DP_GET_SERVICE_FAILED;
        }
        ret = (dpService->*method)(std::forward<Args>(args)...);
        if (retryErrCodes_.count(ret) == 0) {
            break;
        }
    }
    HILOGI("retry end, reason:%{public}d", ret);
    return ret;
}

void DistributedDeviceProfileClient::ReleaseResource()
{
    ReleaseSubscribeDeviceProfileSA();
    ReleaseSubscribePinCodeInvalid();
    ReleaseSubscribeDeviceProfileInited();
    ReleaseDeathRecipient();
    ReleaseRegisterBusinessCallback();
}

void DistributedDeviceProfileClient::StartThreadReRegisterBusinessCallback()
{
    HILOGI("Send Register Business Callback cache in proxy to service!");
    std::thread(&DistributedDeviceProfileClient::ReRegisterBusinessCallback, this).detach();
}

void DistributedDeviceProfileClient::ReRegisterBusinessCallback()
{
    HILOGI("call");
    std::string saId = "";
    std::string businessKey = "";
    sptr<IBusinessCallback> businessCallback = nullptr;
    {
        std::lock_guard<std::mutex> lock(businessLock_);
        if (businessCallback_ == nullptr) {
            HILOGI("not use Retry Register Business Callback");
            return;
        }
        saId = strSaId_;
        businessKey = businessKey_;
        businessCallback = businessCallback_;
    }
    int32_t ret = RegisterBusinessCallback(saId, businessKey, businessCallback);
    if (ret != DP_SUCCESS) {
        HILOGE("Retry Register Business Callback failed");
        return;
    }
    HILOGI("Retry Register Business Callback succeed");
}

void DistributedDeviceProfileClient::ReleaseRegisterBusinessCallback()
{
    std::string saId = "";
    std::string businessKey = "";
    {
        std::lock_guard<std::mutex> lock(businessLock_);
        if (businessCallback_ == nullptr) {
            return;
        }
        saId = strSaId_;
        businessKey = businessKey_;
    }

    int32_t ret = UnRegisterBusinessCallback(saId, businessKey);
    if (ret != DP_SUCCESS) {
        HILOGE("unRegisterBusinessCallback failed, ret=%{public}d", ret);
        return;
    }

    HILOGD("ReleaseRegisterBusinessCallback success");
}

int32_t DistributedDeviceProfileClient::RegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey, sptr<IBusinessCallback> businessCallback)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (saId.empty() || businessKey.empty() || businessCallback == nullptr) {
        HILOGE("Invalid parameters: saId or businessKey is empty, or businessCallback is nullptr");
        return DP_INVALID_PARAM;
    }
    sptr<IRemoteObject> innerBusinessCallback = businessCallback->AsObject();
    if (innerBusinessCallback == nullptr) {
        HILOGE("businessCallback ipc cast fail!");
        return DP_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(businessLock_);
        int32_t ret = dpService->RegisterBusinessCallback(saId, businessKey, innerBusinessCallback);
        if (ret != DP_SUCCESS) {
            HILOGE("Subscribe DP Inited failed!");
            return ret;
        }
        strSaId_ = saId;
        businessKey_ = businessKey;
        businessCallback_ = businessCallback;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::UnRegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey)
{
    {
        std::lock_guard<std::mutex> lock(businessLock_);
        if (businessCallback_ == nullptr) {
            HILOGE("not subscribe pincode invalid, no need unsubscribe pincode invalid");
            return DP_SUCCESS;
        }
    }
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (saId.empty() || businessKey.empty()) {
        HILOGE("Invalid parameters: saId or businessKey is empty");
        return DP_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(businessLock_);
        int32_t ret = dpService->UnRegisterBusinessCallback(saId, businessKey);
        if (ret != DP_SUCCESS) {
            HILOGE("Unsubscribe DP Inited failed!");
            businessCallback_ = nullptr;
            return ret;
        }
        businessCallback_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileClient::PutBusinessEvent(const BusinessEvent& event)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutBusinessEvent(event);
}

int32_t DistributedDeviceProfileClient::GetBusinessEvent(BusinessEvent& event)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetBusinessEvent(event);
}

//delete start
int32_t DistributedDeviceProfileClient::PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfoProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutServiceInfoProfile(serviceInfoProfile);
}

int32_t DistributedDeviceProfileClient::DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->DeleteServiceInfoProfile(regServiceId, userId);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileByServiceId(int64_t serviceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileByServiceId(serviceId, serviceInfoProfile);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileByTokenId(int64_t tokenId,
    std::vector<ServiceInfoProfileNew>& serviceInfoProfiles)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileByTokenId(tokenId, serviceInfoProfiles);
}

int32_t DistributedDeviceProfileClient::GetServiceInfoProfileByRegServiceId(int32_t regServiceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfoProfileByRegServiceId(regServiceId, serviceInfoProfile);
}
//delete end

int32_t DistributedDeviceProfileClient::PutServiceInfo(const ServiceInfo& serviceInfo)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->PutServiceInfo(serviceInfo);
}

int32_t DistributedDeviceProfileClient::DeleteServiceInfo(const UserInfo& userInfo)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->DeleteServiceInfo(userInfo);
}

int32_t DistributedDeviceProfileClient::GetAllServiceInfoList(std::vector<ServiceInfo> &serviceInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetAllServiceInfoList(serviceInfos);
}

int32_t DistributedDeviceProfileClient::GetServiceInfosByUserInfo(const UserInfo& userInfo,
    std::vector<ServiceInfo>& serviceInfos)
{
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    return dpService->GetServiceInfosByUserInfo(userInfo, serviceInfos);
}

void DistributedDeviceProfileClient::ReSubscribeAllServiceInfo()
{
    int32_t saId = 0;
    sptr<IRemoteObject> listener = nullptr;
    {
        std::lock_guard<std::mutex> lock(serInfolistenerLock_);
        if (serviceInfolistener_ == nullptr) {
            HILOGI("not use Retry subscribe dp callback");
            return;
        }
        saId = serviceInfoSaId_;
        listener = serviceInfolistener_;
    }
    auto autoTask = [this, saId, listener] () {
        int32_t ret = SubscribeAllServiceInfo(saId, listener);
        if (ret != DP_SUCCESS) {
            HILOGE("Retry subscribe dp serviceInfo callback failed");
        } else {
            HILOGD("Retry subscribe dp serviceInfo callback succeed");
        }
    };
    std::thread(autoTask).detach();
}

int32_t DistributedDeviceProfileClient::SubscribeAllServiceInfo(int32_t saId, sptr<IRemoteObject> listener)
{
    HILOGI("enter, saId:%{public}d", saId);
    SubscribeDeviceProfileSA();
    auto dpService = GetDeviceProfileService();
    if (dpService == nullptr) {
        HILOGE("Get dp service failed");
        return DP_GET_SERVICE_FAILED;
    }
    if (saId <= 0 || saId > MAX_SAID) {
        HILOGE("saId is invalid, saId:%{public}d", saId);
        return DP_INVALID_PARAM;
    }
    if (listener == nullptr) {
        HILOGE("listener is nullptr!");
        return DP_INVALID_PARAM;
    }
    
    {
        std::lock_guard<std::mutex> lock(serInfolistenerLock_);
        int32_t ret = dpService->SubscribeAllServiceInfo(saId, listener);
        if (ret != DP_SUCCESS) {
            HILOGE("Subscribe DP serviceInfo callback failed!");
            return ret;
        }
        serviceInfoSaId_ = saId;
        serviceInfolistener_ = listener;
    }
    HILOGD("Subscribe DP serviceInfo callback succeed!");
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS