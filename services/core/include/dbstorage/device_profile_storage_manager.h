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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H

#include <atomic>
#include <map>

#include "device_profile_storage.h"
#include "event_handler.h"
#include "kvstore_death_recipient.h"
#include "online_sync_table.h"
#include "service_characteristic_profile.h"
#include "single_instance.h"

#include "dp_device_manager.h"
#include "sync_options.h"

#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
enum class KeyType : int8_t {
    UNKNOWN = -1,
    SERVICE = 0,
    SERVICE_LIST = 1,
    DEVICE_INFO = 2
};

class DeviceProfileStorageManager {
    DECLARE_SINGLE_INSTANCE(DeviceProfileStorageManager);
    friend class DeviceProfile::DpDeviceManager;

public:
    bool Init();
    void OnKvStoreInitDone();

    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile);
    int32_t DeleteDeviceProfile(const std::string& serviceId);
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile);
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions,
        const sptr<IRemoteObject>& profileEventNotifier);

    int32_t SubscribeKvStore(const std::shared_ptr<DistributedKv::KvStoreObserver>& observer);
    int32_t UnSubscribeKvStore(const std::shared_ptr<DistributedKv::KvStoreObserver>& observer);
    int32_t RegisterSyncCallback(const std::shared_ptr<DistributedKv::KvStoreSyncCallback>& sycnCb);
    int32_t UnRegisterSyncCallback();
    void NotifySyncCompleted();
    void NotifySubscriberDied(const sptr<IRemoteObject>& profileEventNotifier);
    int32_t RemoveUnBoundDeviceProfile(const std::string& udid);
    void DumpLocalProfile(std::string& result);

private:
    bool WaitKvDataService();
    void RestoreServiceItemLocked(const std::string& value);
    void RegisterCallbacks();
    void FlushProfileItems();
    std::string GenerateKey(const std::string& udid, const std::string& key, KeyType keyType);

    bool CheckSyncOption(const SyncOptions& syncOptions);
    int32_t NotifySyncStart(const sptr<IRemoteObject>& profileEventNotifier);
    void SetServiceType(const std::string& udid, const std::string& serviceId, ServiceCharacteristicProfile& profile);
    void ReportBehaviorEvent(const std::string& event);
    void ReportFaultEvent(const std::string& event, const std::string& key, const int32_t result);

private:
    std::mutex serviceLock_;
    std::mutex callbackLock_;
    nlohmann::json servicesJson_;
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_;
    std::shared_ptr<AppExecFwk::EventHandler> storageHandler_;
    sptr<IRemoteObject::DeathRecipient> kvStoreDeathRecipient_;
    std::string localUdid_;
    std::map<std::string, std::string> profileItems_;
    std::atomic<bool> kvDataServiceFailed_ {false};
    std::atomic<bool> inited_ {false};
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_;
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> kvStoreSyncCallback_;
    std::mutex profileSyncLock_;
    sptr<IRemoteObject> syncEventNotifier_;
    std::atomic<bool> isSync_ {false};
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H