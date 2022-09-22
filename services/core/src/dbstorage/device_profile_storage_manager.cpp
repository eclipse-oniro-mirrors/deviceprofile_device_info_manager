/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "device_profile_storage_manager.h"

#include <chrono>
#include <thread>

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_utils.h"
#include "dp_device_manager.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
#include "sync_coordinator.h"

#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "subscribe_info.h"
#include "subscribe_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::HiviewDFX;
using namespace std::chrono_literals;
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "DeviceProfileStorageManager";

const std::string SERVICE_TYPE = "type";
const std::string SERVICES = "services";
const std::string DOMAIN_NAME = std::string(HiSysEvent::Domain::DEVICE_PROFILE);
const std::string DEVICE_PROFILE_SYNC_FAILED = "DEVICE_PROFILE_SYNC_FAILED";
const std::string DEVICE_PROFILE_SYNC_EVENT = "DEVICE_PROFILE_SYNC_EVENT";
const std::string FAULT_CODE_KEY = "FAULT_CODE";
const std::string DP_DEVICE_PUT_TRACE = "DP_DEVICE_PUT";
const std::string DP_DEVICE_GET_TRACE = "DP_DEVICE_GET";
const std::string DP_DEVICE_DELETE_TRACE = "DP_DEVICE_DELETE";
const std::string DP_DEVICE_SYNC_TRACE = "DP_DEVICE_SYNC";
constexpr int32_t RETRY_TIMES_WAIT_KV_DATA = 30;
constexpr int32_t FIX_TASK_ID = 0;
constexpr int32_t INDENT = -1;
const char INDENT_CHAR = ' ';
}

IMPLEMENT_SINGLE_INSTANCE(DeviceProfileStorageManager);

bool DeviceProfileStorageManager::Init()
{
    if (!inited_) {
        if (!SyncCoordinator::GetInstance().Init()) {
            HILOGE("SyncCoordinator init failed");
            return false;
        }
        DpDeviceManager::GetInstance().GetLocalDeviceUdid(localUdid_);
        if (localUdid_.empty()) {
            HILOGE("get local udid failed");
            return false;
        }
        onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
        kvStoreDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new KvStoreDeathRecipient());
        auto runner = AppExecFwk::EventRunner::Create("dpstorage");
        storageHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
        if (storageHandler_ == nullptr) {
            return false;
        }
        inited_ = true;
    }

    auto waitTask = [this]() {
        if (!WaitKvDataService()) {
            std::lock_guard<std::mutex> autoLock(serviceLock_);
            profileItems_.clear();
            kvDataServiceFailed_ = true;
            return;
        }
        auto callback = std::bind(&DeviceProfileStorageManager::OnKvStoreInitDone, this);
        onlineSyncTbl_->RegisterKvStoreInitCallback(callback);
        onlineSyncTbl_->Init();
    };
    if (!storageHandler_->PostTask(waitTask)) {
        HILOGE("post task failed");
        return false;
    }
    HILOGI("init succeeded");
    return true;
}

bool DeviceProfileStorageManager::WaitKvDataService()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgrProxy failed");
        return false;
    }
    int32_t retryTimes = RETRY_TIMES_WAIT_KV_DATA;
    do {
        auto kvDataSvr = samgrProxy->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
        if (kvDataSvr != nullptr) {
            IPCObjectProxy* proxy = reinterpret_cast<IPCObjectProxy*>(kvDataSvr.GetRefPtr());
            if (proxy != nullptr && !proxy->IsObjectDead()) {
                HILOGI("get service succeed");
                proxy->AddDeathRecipient(kvStoreDeathRecipient_);
                return true;
            }
        }
        HILOGD("waiting for service...");
        std::this_thread::sleep_for(1s);
        if (--retryTimes <= 0) {
            HILOGE("waiting service timeout(30)s");
            return false;
        }
    } while (true);
    return false;
}

std::string DeviceProfileStorageManager::GenerateKey(const std::string& udid,
    const std::string& key, KeyType keyType)
{
    std::string tmp;
    tmp.append(udid).append("/").append(std::to_string(static_cast<int8_t>(keyType))).append("/").append(key);
    return tmp;
}

int32_t DeviceProfileStorageManager::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    HITRACE_METER_NAME(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_PUT_TRACE);
    if (kvDataServiceFailed_ || onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    std::vector<std::string> keys;
    std::vector<std::string> values;
    std::string serviceId = profile.GetServiceId();
    keys.emplace_back(GenerateKey(localUdid_, serviceId, KeyType::SERVICE));
    values.emplace_back(profile.GetCharacteristicProfileJson());
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (servicesJson_[serviceId] == nullptr) {
        nlohmann::json j;
        j[SERVICE_TYPE] = profile.GetServiceType();
        servicesJson_[serviceId] = j;
        keys.emplace_back(GenerateKey(localUdid_, SERVICES, KeyType::SERVICE_LIST));
        values.emplace_back(servicesJson_.dump(INDENT, INDENT_CHAR, false,
            nlohmann::json::error_handler_t::ignore));
    }

    int32_t errCode = ERR_OK;
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_SUCCEED) {
        autoLock.unlock();
        if (keys.size() > 1) {
            errCode = onlineSyncTbl_->PutDeviceProfileBatch(keys, values);
        } else {
            errCode = onlineSyncTbl_->PutDeviceProfile(keys[0], values[0]);
        }
    } else {
        for (size_t i = 0; i < keys.size(); i++) {
            profileItems_[keys[i]] = values[i];
        }
    }
    return errCode;
}

int32_t DeviceProfileStorageManager::GetDeviceProfile(const std::string& udid,
    const std::string& serviceId, ServiceCharacteristicProfile& profile)
{
    HITRACE_METER_NAME(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_GET_TRACE);
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    std::string key;
    std::string value;
    int32_t result = ERR_OK;
    if (udid.empty()) {
        key = GenerateKey(localUdid_, serviceId, KeyType::SERVICE);
        SetServiceType(udid, serviceId, profile);
    } else {
        std::string queryUdid;
        if (!DpDeviceManager::GetInstance().TransformDeviceId(udid, queryUdid,
            DeviceIdType::UDID)) {
            HILOGE("transform to networkid failed");
            return ERR_DP_INVALID_PARAMS;
        }
        key = GenerateKey(queryUdid, serviceId, KeyType::SERVICE);
        SetServiceType(queryUdid, serviceId, profile);
    }
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    auto itItem = profileItems_.find(key);
    if (itItem != profileItems_.end()) {
        value = profileItems_[key];
    } else {
        autoLock.unlock();
        result = onlineSyncTbl_->GetDeviceProfile(key, value);
    }
    profile.SetServiceId(serviceId);
    profile.SetCharacteristicProfileJson(value);
    return result;
}

void DeviceProfileStorageManager::SetServiceType(const std::string& udid,
    const std::string& serviceId, ServiceCharacteristicProfile& profile)
{
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (udid.empty()) {
        auto jsonData = servicesJson_[serviceId];
        if (jsonData != nullptr) {
            profile.SetServiceType(jsonData[SERVICE_TYPE]);
        }
        return;
    }

    std::string value;
    std::string key = GenerateKey(udid, SERVICES, KeyType::SERVICE_LIST);
    int32_t result = onlineSyncTbl_->GetDeviceProfile(key, value);
    if (result != ERR_OK) {
        HILOGE("get service type failed");
        return;
    }
    auto jsonData = nlohmann::json::parse(value, nullptr, false);
    if (jsonData.is_discarded()) {
        HILOGE("parse error");
        return;
    }
    auto typeData = jsonData[serviceId];
    if (typeData != nullptr && typeData[SERVICE_TYPE] != nullptr) {
        profile.SetServiceType(typeData[SERVICE_TYPE]);
    }
}

int32_t DeviceProfileStorageManager::DeleteDeviceProfile(const std::string& serviceId)
{
    HITRACE_METER_NAME(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_DELETE_TRACE);
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (servicesJson_[serviceId] == nullptr) {
        HILOGW("can't find service %{public}s", serviceId.c_str());
        return ERR_DP_INVALID_PARAMS;
    }
    nlohmann::json original = servicesJson_[serviceId];
    servicesJson_.erase(serviceId);
    std::string servicesKey = GenerateKey(localUdid_, SERVICES, KeyType::SERVICE_LIST);
    std::string servicesValue = servicesJson_.dump();
    int32_t errCode = ERR_OK;
    std::string serviceKey = GenerateKey(localUdid_, serviceId, KeyType::SERVICE);
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_SUCCEED) {
        errCode = onlineSyncTbl_->DeleteDeviceProfile(serviceKey);
        if (errCode != ERR_OK) {
            servicesJson_[serviceId] = std::move(original);
            return errCode;
        }
        errCode = onlineSyncTbl_->PutDeviceProfile(servicesKey, servicesValue);
        if (errCode != ERR_OK) {
            HILOGW("update services failed, errorCode = %{public}d", errCode);
        }
    } else {
        profileItems_.erase(serviceKey);
        profileItems_[servicesKey] = std::move(servicesValue);
    }
    return errCode;
}

int32_t DeviceProfileStorageManager::RemoveUnBoundDeviceProfile(const std::string& udid)
{
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (onlineSyncTbl_->GetInitStatus() != StorageInitStatus::INIT_SUCCEED) {
        HILOGE("kvstore not init");
        return ERR_DP_NOT_INIT_DB;
    }

    int32_t errCode = ERR_OK;
    std::string networkId;
    if (!DpDeviceManager::GetInstance().TransformDeviceId(udid, networkId, DeviceIdType::NETWORKID)) {
        HILOGE("udid transform to networkid failed, udid = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        return ERR_DP_GET_NETWORKID_FAILED;
    }

    errCode = onlineSyncTbl_->RemoveDeviceData(networkId);
    return errCode;
}

int32_t DeviceProfileStorageManager::SyncDeviceProfile(const SyncOptions& syncOptions,
    const sptr<IRemoteObject>& profileEventNotifier)
{
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_FAILED) {
        HILOGE("kvstore init failed");
        return ERR_DP_INIT_DB_FAILED;
    }

    if (!CheckSyncOption(syncOptions)) {
        HILOGW("device list has offline device");
        return ERR_DP_INVALID_PARAMS;
    }

    int32_t result = NotifySyncStart(profileEventNotifier);
    if (result != ERR_OK) {
        return result;
    }

    StartAsyncTrace(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_SYNC_TRACE, FIX_TASK_ID);
    auto syncTask = [syncOptions, this]() {
        HILOGI("start sync");
        ReportBehaviorEvent(DEVICE_PROFILE_SYNC_EVENT);
        auto devicesList = syncOptions.GetDeviceList();
        if (devicesList.empty()) {
            DpDeviceManager::GetInstance().GetDeviceIdList(devicesList);
        }
        SyncCoordinator::GetInstance().SetSyncTrigger(false);
        std::vector<std::string> devicesVector(std::vector<std::string> { devicesList.begin(), devicesList.end() });
        int32_t result = onlineSyncTbl_->SyncDeviceProfile(devicesVector, syncOptions.GetSyncMode());
        if (result != ERR_OK) {
            ReportFaultEvent(DEVICE_PROFILE_SYNC_FAILED, FAULT_CODE_KEY, result);
            HILOGE("sync failed result : %{public}d", result);
            NotifySyncCompleted();
            return;
        }
    };
    if (!SyncCoordinator::GetInstance().DispatchSyncTask(syncTask)) {
        HILOGE("post sync task failed");
        NotifySyncCompleted();
        return ERR_DP_POST_TASK_FAILED;
    }
    return ERR_OK;
}

int32_t DeviceProfileStorageManager::NotifySyncStart(const sptr<IRemoteObject>& profileEventNotifier)
{
    if (!SyncCoordinator::GetInstance().AcquireSync()) {
        HILOGW("sync busy");
        return ERR_DP_DEVICE_SYNC_BUSY;
    }

    {
        std::lock_guard<std::mutex> autoLock(profileSyncLock_);
        syncEventNotifier_ = profileEventNotifier;
    }

    SubscribeInfo subscribeInfo;
    subscribeInfo.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    std::list<SubscribeInfo> subscribeInfos;
    subscribeInfos.emplace_back(subscribeInfo);
    std::list<ProfileEvent> failedEvents;
    if (SubscribeManager::GetInstance().SubscribeProfileEvents(
        subscribeInfos, profileEventNotifier, failedEvents) != ERR_OK) {
        HILOGE("subscribe sync event failed");
        SyncCoordinator::GetInstance().ReleaseSync();
        std::lock_guard<std::mutex> autoLock(profileSyncLock_);
        syncEventNotifier_ = nullptr;
        return ERR_DP_SUBSCRIBE_FAILED;
    }
    return ERR_OK;
}

void DeviceProfileStorageManager::NotifySyncCompleted()
{
    HILOGI("called");
    SyncCoordinator::GetInstance().ReleaseSync();
    FinishAsyncTrace(HITRACE_TAG_DEVICE_PROFILE, DP_DEVICE_SYNC_TRACE, FIX_TASK_ID);
    std::lock_guard<std::mutex> autoLock(profileSyncLock_);
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    std::list<ProfileEvent> failedEvents;
    int32_t ret = SubscribeManager::GetInstance().UnsubscribeProfileEvents(
        profileEvents, syncEventNotifier_, failedEvents);
    if (ret != ERR_OK) {
        HILOGW("unsubscribe sync event failed");
    }
    syncEventNotifier_ = nullptr;
}

void DeviceProfileStorageManager::NotifySubscriberDied(const sptr<IRemoteObject>& profileEventNotifier)
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(profileSyncLock_);
    if (profileEventNotifier != syncEventNotifier_) {
        return;
    }

    SyncCoordinator::GetInstance().ReleaseSync();
    syncEventNotifier_ = nullptr;
}

bool DeviceProfileStorageManager::CheckSyncOption(const SyncOptions& syncOptions)
{
    std::list<std::shared_ptr<DeviceInfo>> onlineDevices;
    DpDeviceManager::GetInstance().GetDeviceList(onlineDevices);
    std::list<std::string> onlineDeviceIds;
    for (const auto& onlineDevice : onlineDevices) {
        onlineDeviceIds.emplace_back(onlineDevice->GetDeviceId());
    }

    // check whether deviceId is online
    auto syncDeviceIds = syncOptions.GetDeviceList();
    for (const auto& syncDeviceId : syncDeviceIds) {
        auto iter = find(onlineDeviceIds.begin(), onlineDeviceIds.end(), syncDeviceId);
        if (iter == onlineDeviceIds.end()) {
            HILOGE("deviceId: %{public}s is not online", DeviceProfileUtils::AnonymizeDeviceId(syncDeviceId).c_str());
            return false;
        }
    }
    return true;
}

void DeviceProfileStorageManager::RestoreServiceItemLocked(const std::string& value)
{
    auto restoreItems = nlohmann::json::parse(value, nullptr, false);
    if (restoreItems.is_discarded()) {
        HILOGE("parse error");
        return;
    }
    for (const auto& [key, value] : servicesJson_.items()) {
        restoreItems[key] = value;
    }
    servicesJson_ = std::move(restoreItems);
}

void DeviceProfileStorageManager::FlushProfileItems()
{
    std::string services;
    std::string servicesKey = GenerateKey(localUdid_, SERVICES, KeyType::SERVICE_LIST);
    int32_t errCode = onlineSyncTbl_->GetDeviceProfile(servicesKey, services);
    std::unique_lock<std::mutex> autoLock(serviceLock_);
    if (errCode == ERR_OK) {
        RestoreServiceItemLocked(services);
    }

    std::vector<std::string> keys;
    std::vector<std::string> values;
    size_t itemSize = profileItems_.size();
    HILOGI("profile item size = %{public}zu", itemSize);
    if (itemSize == 0) {
        return;
    }
    keys.reserve(itemSize);
    values.reserve(itemSize);
    // update service list to avoid overwriting the value in db storage
    profileItems_[servicesKey] = servicesJson_.dump();
    for (const auto& [key, value] : profileItems_) {
        keys.emplace_back(key);
        values.emplace_back(value);
    }
    profileItems_.clear();
    autoLock.unlock();

    errCode = onlineSyncTbl_->PutDeviceProfileBatch(keys, values);
    if (errCode != ERR_OK) {
        HILOGE("put failed, errCode = %{public}d", errCode);
    }
}

void DeviceProfileStorageManager::RegisterCallbacks()
{
    HILOGI("called");
    int32_t errCode = ERR_OK;
    if (kvStoreObserver_ != nullptr) {
        errCode = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
        HILOGI("SubscribeKvStore errCode = %{public}d", errCode);
    }
    if (kvStoreSyncCallback_ != nullptr) {
        errCode = onlineSyncTbl_->RegisterSyncCallback(kvStoreSyncCallback_);
        HILOGI("RegisterSyncCallback errCode = %{public}d", errCode);
    }
}

void DeviceProfileStorageManager::OnKvStoreInitDone()
{
    RegisterCallbacks();
    FlushProfileItems();
}

int32_t DeviceProfileStorageManager::SubscribeKvStore(const std::shared_ptr<KvStoreObserver>& observer)
{
    std::lock_guard<std::mutex> autoLock(callbackLock_);
    kvStoreObserver_ = observer;
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_SUCCEED) {
        return onlineSyncTbl_->SubscribeKvStore(observer);
    }
    return ERR_OK;
}

int32_t DeviceProfileStorageManager::UnSubscribeKvStore(const std::shared_ptr<KvStoreObserver>& observer)
{
    std::lock_guard<std::mutex> autoLock(callbackLock_);
    kvStoreObserver_ = nullptr;
    return onlineSyncTbl_->UnSubscribeKvStore(observer);
}

int32_t DeviceProfileStorageManager::RegisterSyncCallback(const std::shared_ptr<KvStoreSyncCallback>& sycnCb)
{
    std::lock_guard<std::mutex> autoLock(callbackLock_);
    kvStoreSyncCallback_ = sycnCb;
    if (onlineSyncTbl_->GetInitStatus() == StorageInitStatus::INIT_SUCCEED) {
        return onlineSyncTbl_->RegisterSyncCallback(sycnCb);
    }
    return ERR_OK;
}

int32_t DeviceProfileStorageManager::UnRegisterSyncCallback()
{
    std::lock_guard<std::mutex> autoLock(callbackLock_);
    kvStoreSyncCallback_ = nullptr;
    return onlineSyncTbl_->UnRegisterSyncCallback();
}

void DeviceProfileStorageManager::ReportBehaviorEvent(const std::string& event)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, event, HiSysEvent::EventType::BEHAVIOR);
    if (ret != 0) {
        HILOGE("hisysevent write failed! ret %{public}d.", ret);
    }
}

void DeviceProfileStorageManager::ReportFaultEvent(const std::string& event,
    const std::string& key, const int32_t result)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, event, HiSysEvent::EventType::FAULT, key, result);
    if (ret != 0) {
        HILOGE("hisysevent write failed! ret %{public}d.", ret);
    }
}

void DeviceProfileStorageManager::DumpLocalProfile(std::string& result)
{
    for (const auto& [key, value] : servicesJson_.items()) {
        result.append("key:");
        result.append(key);
        result.append(" value:");
        result.append(value.dump());
        result.append("\n");
    }
}
} // namespace DeviceProfile
} // namespace OHOS
