/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_KV_ADAPTER_H
#define OHOS_DM_KV_ADAPTER_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "distributed_kv_data_manager.h"
#include "ikv_adapter.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class BusinessEventAdapter : public DistributedDeviceProfile::IKVAdapter{
public:
    BusinessEventAdapter(
        const std::shared_ptr<DistributedKv::KvStoreDeathRecipient> &deathListener, DistributedKv::DataType dataType);
    
    int32_t Init() override;
    int32_t UnInit() override;
    int32_t ReInit();
    int32_t Put(const std::string& key, const std::string& value) override;
    int32_t Get(const std::string& key, std::string& value) override;
    int32_t DeleteBatch(const std::vector<std::string>& keys) override;
    int32_t PutBatch(const std::map<std::string, std::string>& values) override;
    int32_t Delete(const std::string& key) override;
    int32_t DeleteByPrefix(const std::string& keyPrefix) override;
    int32_t GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values) override;
    int32_t Sync(const std::vector<std::string>& deviceList, SyncMode syncMode) override;
    int32_t GetDeviceEntries(const std::string& udid, std::map<std::string, std::string>& values) override;
    int32_t RemoveDeviceData(const std::string& uuid) override;
    void OnRemoteDied();

private:
    DistributedKv::Status GetKvStorePtr();
    int32_t RegisterKvStoreDeathListener();
    int32_t UnregisterKvStoreDeathListener();

private:
    DistributedKv::AppId appId_;
    DistributedKv::StoreId storeId_;
    DistributedKv::DistributedKvDataManager kvDataMgr_;
    DistributedKv::DataType dataType_ = DistributedKv::DataType::TYPE_STATICS;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient_ = nullptr;
    std::mutex BusinessAdapterMutex_;
    std::atomic<bool> isInited_ = false;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DP_BUSINESS_EVENT_ADAPTER_H
