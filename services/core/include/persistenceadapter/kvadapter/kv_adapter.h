/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_KV_ADAPTER_H
#define OHOS_DP_KV_ADAPTER_H

#include <condition_variable>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "distributed_kv_data_manager.h"
#include "kvstore_observer.h"
#include "types.h"

#include "distributed_device_profile_enums.h"
#include "ikv_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class KVAdapter : public IKVAdapter {
public:
    KVAdapter(const std::string &appId, const std::string &storeId,
        const std::shared_ptr<DistributedKv::KvStoreObserver> &dataChangeListener,
        const std::shared_ptr<DistributedKv::KvStoreSyncCallback> &syncCompletedListener,
        const std::shared_ptr<DistributedKv::KvStoreDeathRecipient> &deathListener,
        DistributedKv::DataType dataType);
    virtual ~KVAdapter();

    int32_t Init() override;
    int32_t UnInit() override;
    int32_t Put(const std::string& key, const std::string& value) override;
    int32_t PutBatch(const std::map<std::string, std::string>& values) override;
    int32_t Delete(const std::string& key) override;
    int32_t DeleteByPrefix(const std::string& keyPrefix) override;
    int32_t Get(const std::string& key, std::string& value) override;
    int32_t GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values) override;
    int32_t Sync(const std::vector<std::string>& deviceList, SyncMode syncMode) override;
    int32_t GetDeviceEntries(const std::string& uuid, std::map<std::string, std::string>& values) override;
    int32_t DeleteBatch(const std::vector<std::string>& keys) override;
    int32_t DeleteKvStore();

private:
    DistributedKv::Status GetKvStorePtr(DistributedKv::DataType dataType);
    int32_t DeleteKvStorePtr();
    int32_t RegisterDataChangeListener();
    int32_t UnRegisterDataChangeListener();
    int32_t DeleteDataChangeListener();
    int32_t RegisterSyncCompletedListener();
    int32_t UnRegisterSyncCompletedListener();
    int32_t DeleteSyncCompletedListener();
    int32_t RegisterDeathListener();
    int32_t UnRegisterDeathListener();
    int32_t DeleteDeathListener();

private:
    DistributedKv::AppId appId_;
    DistributedKv::StoreId storeId_;
    DistributedKv::DistributedKvDataManager kvDataMgr_;
    DistributedKv::DataType dataType_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> dataChangeListener_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCompletedListener_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient_ = nullptr;
    std::mutex kvAdapterMutex_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_KV_ADAPTER_H
