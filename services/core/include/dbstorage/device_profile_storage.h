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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_H

#include <atomic>
#include <shared_mutex>

#include "sync_options.h"

#include "distributed_kv_data_manager.h"
#include "event_handler.h"
#include "kvstore_observer.h"
#include "kvstore_sync_callback.h"

namespace OHOS {
namespace DeviceProfile {
enum class StorageInitStatus {
    UNINITED = 1,
    INIT_FAILED = 2,
    INIT_SUCCEED = 3
};

class DeviceProfileStorage {
public:
    using KvStoreInitCallback = std::function<void()>;

    DeviceProfileStorage(const std::string& appId, const std::string& storeId);
    virtual ~DeviceProfileStorage() = default;

    virtual void Init();
    virtual int32_t GetDeviceProfile(const std::string& key, std::string& value);
    virtual int32_t DeleteDeviceProfile(const std::string& key);
    virtual int32_t PutDeviceProfile(const std::string& key, const std::string& value);
    virtual int32_t PutDeviceProfileBatch(const std::vector<std::string>& keys,
        const std::vector<std::string>& values);
    virtual int32_t SyncDeviceProfile(const std::vector<std::string>& deviceIdList,
        SyncMode syncMode);
    virtual int32_t RemoveDeviceData(const std::string networkId);
    virtual int32_t RegisterSyncCallback(const std::shared_ptr<DistributedKv::KvStoreSyncCallback>& sycnCb);
    virtual int32_t UnRegisterSyncCallback();

    void SetOptions(const DistributedKv::Options& options);
    StorageInitStatus GetInitStatus();
    bool RegisterKvStoreInitCallback(const KvStoreInitCallback& callback);
    int32_t SubscribeKvStore(const std::shared_ptr<DistributedKv::KvStoreObserver>& observer);
    int32_t UnSubscribeKvStore(const std::shared_ptr<DistributedKv::KvStoreObserver>& observer);

private:
    bool TryGetKvStore();
    bool InitKvStore();
    DistributedKv::Status GetKvStore();
    void DeleteKvStore();
    void SubscribeDeviceProfileKvStore();
    bool CheckTrustGroup(const std::vector<std::string>& deviceIdList);

private:
    DistributedKv::Options options_;
    DistributedKv::AppId appId_;
    DistributedKv::StoreId storeId_;
    DistributedKv::DistributedKvDataManager dataManager_;

    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    std::atomic<StorageInitStatus> initStatus_ {StorageInitStatus::UNINITED};
    KvStoreInitCallback kvStoreInitCallback_;
    std::shared_mutex storageLock_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_H
