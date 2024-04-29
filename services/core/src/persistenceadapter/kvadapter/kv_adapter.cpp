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

#include <cinttypes>
#include <mutex>

#include "datetime_ex.h"
#include "string_ex.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "kv_adapter.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedKv;
namespace {
    constexpr int32_t MAX_INIT_RETRY_TIMES = 30;
    constexpr int32_t INIT_RETRY_SLEEP_INTERVAL = 500 * 1000; // 500ms
    const std::string DATABASE_DIR = "/data/service/el1/public/database/distributed_device_profile_service";
    const std::string TAG = "KVAdapter";
}

KVAdapter::KVAdapter(const std::string &appId, const std::string &storeId,
    const std::shared_ptr<DistributedKv::KvStoreObserver> &dataChangeListener,
    const std::shared_ptr<DistributedKv::KvStoreSyncCallback> &syncCompletedListener,
    const std::shared_ptr<DistributedKv::KvStoreDeathRecipient> &deathListener)
{
    this->appId_.appId = appId;
    this->storeId_.storeId = storeId;
    this->dataChangeListener_ = dataChangeListener;
    this->syncCompletedListener_= syncCompletedListener;
    this->deathRecipient_ = deathListener;
    HILOGI("KVAdapter Constructor Success, appId: %{public}s, storeId: %{public}s", appId.c_str(), storeId.c_str());
}

KVAdapter::~KVAdapter()
{
    HILOGI("KVAdapter Destruction!");
}

int32_t KVAdapter::Init()
{
    HILOGI("Init kvAdapter, storeId: %{public}s", storeId_.storeId.c_str());
    int32_t tryTimes = MAX_INIT_RETRY_TIMES;
    int64_t beginTime = GetTickCount();
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStorePtr();
        if (kvStorePtr_ && status == DistributedKv::Status::SUCCESS) {
            int64_t endTime = GetTickCount();
            HILOGI("Init KvStorePtr Success, spend %{public}" PRId64 " ms", endTime - beginTime);
            RegisterSyncCompletedListener();
            RegisterDataChangeListener();
            RegisterDeathListener();
            return DP_SUCCESS;
        }
        HILOGI("CheckKvStore, left times: %{public}d, status: %{public}d", tryTimes, status);
        if (status == DistributedKv::Status::SECURITY_LEVEL_ERROR) {
            DeleteKvStore();
        }
        usleep(INIT_RETRY_SLEEP_INTERVAL);
        tryTimes--;
    }
    return DP_KV_DB_INIT_FAIL;
}

int32_t KVAdapter::UnInit()
{
    HILOGI("DBAdapter UnInit");
    UnRegisterSyncCompletedListener();
    UnRegisterDataChangeListener();
    UnRegisterDeathListener();
    DeleteSyncCompletedListener();
    DeleteDataChangeListener();
    DeleteDeathListener();
    DeleteKvStorePtr();
    return DP_SUCCESS;
}

int32_t KVAdapter::Put(const std::string& key, const std::string& value)
{
    if (key.empty() || key.size() > MAX_STRING_LEN || value.empty() || value.size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid!");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvDBPtr is null!");
            return DP_KV_DB_PTR_NULL;
        }

        DistributedKv::Key kvKey(key);
        DistributedKv::Value oldV;
        if (kvStorePtr_->Get(kvKey, oldV) == DistributedKv::Status::SUCCESS && oldV.ToString() == value) {
            HILOGD("The key-value pair already exists. key=%{public}s,value=%{public}s",
                ProfileUtils::GetAnonyString(key).c_str(),
                ProfileUtils::GetAnonyString(value).c_str());
            return DP_SUCCESS;
        }

        DistributedKv::Value kvValue(value);
        status = kvStorePtr_->Put(kvKey, kvValue);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Put kv to db failed, ret: %{public}d", status);
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::PutBatch(const std::map<std::string, std::string>& values)
{
    if (values.empty() || values.size() > MAX_PROFILE_SIZE) {
        HILOGE("Param is invalid!");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvDBPtr is null!");
            return DP_KV_DB_PTR_NULL;
        }
        std::vector<DistributedKv::Entry> entries;
        DistributedKv::Value oldV;
        DistributedKv::Key kvKey;
        for (auto item : values) {
            kvKey = item.first;
            if (kvStorePtr_->Get(kvKey, oldV) == DistributedKv::Status::SUCCESS && oldV.ToString() == item.second) {
                HILOGD("The key-value pair already exists. key=%{public}s,value=%{public}s",
                    ProfileUtils::GetAnonyString(item.first).c_str(),
                    ProfileUtils::GetAnonyString(item.second).c_str());
                continue;
            }

            Entry entry;
            entry.key = kvKey;
            entry.value = item.second;
            entries.emplace_back(entry);
        }
        if (entries.empty()) {
            HILOGD("All key-value pair already exists.");
            return DP_SUCCESS;
        }
        status = kvStorePtr_->PutBatch(entries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("PutBatch kv to db failed, ret: %{public}d", status);
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::Delete(const std::string& key)
{
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvDBPtr is null!");
            return DP_KV_DB_PTR_NULL;
        }
        DistributedKv::Key kvKey(key);
        status = kvStorePtr_->Delete(kvKey);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Delete kv by key failed!");
        return DP_DEL_KV_DB_FAIL;
    }
    HILOGI("Delete kv by key success!");
    return DP_SUCCESS;
}

int32_t KVAdapter::Get(const std::string& key, std::string& value)
{
    HILOGI("Get data by key: %{public}s", ProfileUtils::GetAnonyString(key).c_str());
    DistributedKv::Key kvKey(key);
    DistributedKv::Value kvValue;
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->Get(kvKey, kvValue);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Get data from kv failed, key: %{public}s", ProfileUtils::GetAnonyString(key).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    value = kvValue.ToString();
    return DP_SUCCESS;
}

int32_t KVAdapter::GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values)
{
    HILOGI("Get data by key prefix: %{public}s", ProfileUtils::GetAnonyString(keyPrefix).c_str());
    std::lock_guard<std::mutex> lock(kvAdapterMutex_);
    if (kvStorePtr_ == nullptr) {
        HILOGE("kvStoragePtr_ is null");
        return DP_KV_DB_PTR_NULL;
    }
    // if prefix is empty, get all entries.
    DistributedKv::Key allEntryKeyPrefix(keyPrefix);
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Query data by keyPrefix failed, prefix: %{public}s", ProfileUtils::GetAnonyString(keyPrefix).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    if (allEntries.size() == 0 || allEntries.size() > MAX_DB_SIZE) {
        HILOGE("AllEntries size is invalid!");
        return DP_INVALID_PARAMS;
    }
    for (const auto& item : allEntries) {
        values[item.key.ToString()] = item.value.ToString();
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::DeleteByPrefix(const std::string& keyPrefix)
{
    HILOGI("call");
    std::lock_guard<std::mutex> lock(kvAdapterMutex_);
    if (kvStorePtr_ == nullptr) {
        HILOGE("kvStoragePtr_ is null");
        return DP_KV_DB_PTR_NULL;
    }
    // if prefix is empty, get all entries.
    DistributedKv::Key allEntryKeyPrefix(keyPrefix);
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != DistributedKv::Status::SUCCESS) {
        return DP_DEL_KV_DB_FAIL;
    }
    std::vector<DistributedKv::Key> keys;
    for (auto item : allEntries) {
        keys.push_back(item.key);
    }
    status = kvStorePtr_->DeleteBatch(keys);
    if (status != DistributedKv::Status::SUCCESS) {
        return DP_DEL_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

DistributedKv::Status KVAdapter::GetKvStorePtr()
{
    HILOGI("called");
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = true,
        .isPublic = true,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = 1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = DATABASE_DIR
    };
    SyncPolicy syncPolicyOnline {
        .type = PolicyType::IMMEDIATE_SYNC_ON_ONLINE
    };
    options.policies.emplace_back(syncPolicyOnline);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        status = kvDataMgr_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    }
    return status;
}

int32_t KVAdapter::DeleteKvStorePtr()
{
    HILOGI("Delete KvStore Ptr!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvStorePtr_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::Sync(const std::vector<std::string>& deviceList, SyncMode syncMode)
{
    HILOGI("Sync!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStorePtr is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        if (deviceList.empty() || deviceList.size() > MAX_DEVICE_SIZE) {
            HILOGE("deviceList is invalid!");
            return DP_INVALID_PARAMS;
        }
        if (syncMode <= SyncMode::MIN || syncMode >= SyncMode::MAX) {
            HILOGE("syncMode is invalid!");
            return DP_INVALID_PARAMS;
        }
        DistributedKv::Status status = kvStorePtr_->Sync(deviceList, static_cast<DistributedKv::SyncMode>(syncMode));
        if (status != DistributedKv::Status::SUCCESS) {
            HILOGE("Sync fail!");
            return DP_KV_SYNC_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::RegisterDataChangeListener()
{
    HILOGI("Register db data change listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_INVALID_PARAMS;
        }
        DistributedKv::Status status =
            kvStorePtr_->SubscribeKvStore(DistributedKv::SubscribeType::SUBSCRIBE_TYPE_ALL, dataChangeListener_);
        if (status != DistributedKv::Status::SUCCESS) {
            HILOGE("Register db data change listener failed, ret: %{public}d", status);
            return DP_REGISTER_KV_DATA_LISTENER_FAILED;
        }
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::UnRegisterDataChangeListener()
{
    HILOGI("UnRegister db data change listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        DistributedKv::Status status =
            kvStorePtr_->UnSubscribeKvStore(DistributedKv::SubscribeType::SUBSCRIBE_TYPE_ALL, dataChangeListener_);
        if (status != DistributedKv::Status::SUCCESS) {
            HILOGE("UnRegister db data change listener failed, ret: %{public}d", status);
            return DP_UNREGISTER_KV_DATA_LISTENER_FAILED;
        }
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::DeleteDataChangeListener()
{
    HILOGI("Delete DataChangeListener!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        dataChangeListener_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::RegisterSyncCompletedListener()
{
    HILOGI("Register syncCompleted listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        DistributedKv::Status status = kvStorePtr_->RegisterSyncCallback(syncCompletedListener_);
        if (status != DistributedKv::Status::SUCCESS) {
            HILOGE("Register syncCompleted listener failed, ret: %{public}d", status);
            return DP_REGISTER_KV_SYNC_LISTENER_FAILED;
        }
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::UnRegisterSyncCompletedListener()
{
    HILOGI("UnRegister syncCompleted listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        DistributedKv::Status status = kvStorePtr_->UnRegisterSyncCallback();
        if (status != DistributedKv::Status::SUCCESS) {
            HILOGE("UnRegister db data change listener failed, ret: %{public}d", status);
            return DP_UNREGISTER_KV_SYNC_LISTENER_FAILED;
        }
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::DeleteSyncCompletedListener()
{
    HILOGI("Delete SyncCompletedListener!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        syncCompletedListener_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::RegisterDeathListener()
{
    HILOGI("Register syncCompleted listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvDataMgr_.RegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::UnRegisterDeathListener()
{
    HILOGI("UnRegister syncCompleted listener");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvDataMgr_.UnRegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::DeleteDeathListener()
{
    HILOGI("Delete DeathListener!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        deathRecipient_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::DeleteKvStore()
{
    HILOGI("Delete KvStore!");
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        kvDataMgr_.CloseKvStore(appId_, storeId_);
        kvDataMgr_.DeleteKvStore(appId_, storeId_, DATABASE_DIR);
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::GetByPrefix(const std::string& udid, const std::string& keyPrefix,
    std::map<std::string, std::string>& values)
{
    if (udid.empty() || keyPrefix.empty()) {
        HILOGE("udid or keyPrefix is invalid");
        return DP_INVALID_PARAMS;
    }
    HILOGI("Get data by key prefix: %{public}s", ProfileUtils::GetAnonyString(keyPrefix).c_str());
    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> allEntries;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        // if prefix is empty, get all entries.
        DistributedKv::Key allEntryKeyPrefix(keyPrefix);
        status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
        HILOGI("Get data status: %{public}d", status);
    }
    // if data does not exist, GetEntries return SUCCESS, allEntries size is 0.
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Query data by keyPrefix failed, prefix: %{public}s", ProfileUtils::GetAnonyString(keyPrefix).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    // data to be queried must exist, if not, try to sync.
    if (allEntries.size() == 0) {
        HILOGE("AllEntries is empty!");
        SyncDeviceProfile(udid);
        return DP_INVALID_PARAMS;
    }
    if (allEntries.size() > MAX_DB_SIZE) {
        HILOGE("AllEntries size is invalid!");
        return DP_INVALID_PARAMS;
    }
    for (const auto& item : allEntries) {
        values[item.key.ToString()] = item.value.ToString();
    }
    return DP_SUCCESS;
}

int32_t KVAdapter::Get(const std::string& udid, const std::string& key, std::string& value)
{
    if (udid.empty() || key.empty()) {
        HILOGE("udid or key is invalid");
        return DP_INVALID_PARAMS;
    }
    HILOGI("Get data by key: %{public}s", ProfileUtils::GetAnonyString(key).c_str());
    DistributedKv::Key kvKey(key);
    DistributedKv::Value kvValue;
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->Get(kvKey, kvValue);
    }
    if (status == DistributedKv::Status::NOT_FOUND) {
        SyncDeviceProfile(udid);
        return DP_GET_KV_DB_FAIL;
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Get data from kv failed, key: %{public}s", ProfileUtils::GetAnonyString(key).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    value = kvValue.ToString();
    return DP_SUCCESS;
}

void KVAdapter::SyncDeviceProfile(const std::string& udid)
{
    HILOGI("call!");
    if (udid.empty()) {
        HILOGE("udid is invalid.");
        return;
    }
    std::vector<std::string> device;
    device.push_back(udid);
    SyncMode syncMode{ SyncMode::PUSH_PULL };
    int32_t syncResult = Sync(device, syncMode);
    HILOGI("SyncDeviceProfile res: %{public}d!", syncResult);
}
} // namespace DeviceProfile
} // namespace OHOS
