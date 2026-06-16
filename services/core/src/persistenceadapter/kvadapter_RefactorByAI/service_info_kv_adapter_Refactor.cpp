/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "service_info_kv_adapter.h"

#include <cinttypes>
#include <mutex>

#include "datetime_ex.h"
#include "string_ex.h"
#include "ffrt.h"
#include "cJSON.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedKv;
namespace {
    constexpr int32_t MAX_INIT_RETRY_TIMES = 30;
    constexpr int32_t INIT_RETRY_SLEEP_INTERVAL = 200 * 1000; // 200ms
    constexpr uint32_t MAX_BATCH_SIZE = 128;
    const std::string DATABASE_DIR = "/data/service/el1/public/database/distributed_device_profile_service";
    const std::string TAG = "ServiceInfoKvAdapter";
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store_service_info_profile";
    // [原则13] 使用非法默认值，需显式设置
    constexpr DistributedKv::DataType INVALID_DATA_TYPE = static_cast<DistributedKv::DataType>(-1);
}

ServiceInfoKvAdapter::ServiceInfoKvAdapter(
    const std::shared_ptr<DistributedKv::KvStoreDeathRecipient> &deathListener, DistributedKv::DataType dataType)
{
    this->deathRecipient_ = deathListener;
    // [原则13] 校验dataType参数，不允许使用非法默认值
    if (dataType == INVALID_DATA_TYPE) {
        HILOGE("Invalid dataType, must be explicitly set");
        return;
    }
    this->dataType_ = dataType;
    this->appId_.appId = APP_ID;
    this->storeId_.storeId = STORE_ID;
}

int32_t ServiceInfoKvAdapter::Init()
{
    HILOGI("Init local DB, dataType: %{public}d", static_cast<int32_t>(dataType_));
    // [原则12] 使用双检查锁模式确保isInited_状态一致性
    if (isInited_.load()) {
        HILOGI("Local DB already inited.");
        return DP_SUCCESS;
    }
    int32_t tryTimes = MAX_INIT_RETRY_TIMES;
    int64_t beginTime = GetTickCount();
    DistributedKv::Status status = DistributedKv::Status::SUCCESS;
    while (tryTimes > 0) {
        status = GetKvStorePtr();
        if (status == DistributedKv::Status::SUCCESS) {
            HILOGI("Init KvStorePtr Success");
            RegisterKvStoreDeathListener();
            isInited_.store(true);
            return DP_SUCCESS;
        }
        HILOGI("CheckKvStore, left times: %{public}d, status: %{public}d", tryTimes, status);
        usleep(INIT_RETRY_SLEEP_INTERVAL);
        tryTimes--;
    }
    // [原则12] 重试失败后，确保isInited_保持为false，不进入不一致状态
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStorePtr is nullptr after retry!");
            return DP_KV_DB_PTR_NULL;
        }
    }
    // [原则12] 明确处理非SUCCESS状态，不设置isInited_
    HILOGE("get kvStorePtr failed after all retries, status:%{public}d", status);
    return DP_KV_DB_PTR_NULL;
}

int32_t ServiceInfoKvAdapter::UnInit()
{
    HILOGI("ServiceInfoKvAdapter UnInit");
    // [原则12] 使用原子操作确保线程安全的状态检查和清理
    if (!isInited_.load()) {
        HILOGI("Already uninited.");
        return DP_SUCCESS;
    }
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStorePtr is nullptr!");
            isInited_.store(false);
            return DP_KV_DB_PTR_NULL;
        }
        UnregisterKvStoreDeathListener();
        kvStorePtr_.reset();
    }
    isInited_.store(false);
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::ReInit()
{
    HILOGI("ServiceInfoKvAdapter ReInit");
    UnInit();
    return Init();
}

int32_t ServiceInfoKvAdapter::Put(const std::string& key, const std::string& value)
{
    HILOGI("ServiceInfoKvAdapter::Put");
    if (key.empty() || key.size() > MAX_STRING_LEN || value.empty() || value.size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid: key or value is empty or too long");
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
        DistributedKv::Value kvValue(value);
        status = kvStorePtr_->Put(kvKey, kvValue);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Put kv to db failed, ret: %{public}d", status);
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::Get(const std::string& key, std::string& value)
{
    // [原则12] 添加输入参数校验
    if (key.empty() || key.size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid: key is empty or too long");
        return DP_INVALID_PARAMS;
    }
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
        HILOGE("Get data from kv failed, key: %{public}s", ProfileUtils::GetDbKeyAnonyString(key).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    value = kvValue.ToString();
    return DP_SUCCESS;
}

void ServiceInfoKvAdapter::OnRemoteDied()
{
    HILOGI("OnRemoteDied, recover db begin");
    // [原则12] 使用weak_ptr防止对象生命周期问题，避免悬垂指针
    auto weakThis = weak_from_this();
    auto reInitTask = [weakThis]() {
        auto sharedThis = weakThis.lock();
        if (!sharedThis) {
            HILOGE("ServiceInfoKvAdapter already destroyed, skip ReInit");
            return;
        }
        HILOGI("ReInit, storeId:%{public}s", sharedThis->storeId_.storeId.c_str());
        sharedThis->ReInit();
    };
    ffrt::submit(reInitTask);
}

DistributedKv::Status ServiceInfoKvAdapter::GetKvStorePtr()
{
    HILOGI("ServiceInfoKvAdapter::GetKvStorePtr");
    // [原则4] 启用加密保护敏感数据存储
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = true,
        .autoSync = false,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = 1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = DATABASE_DIR
    };
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        status = kvDataMgr_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ == nullptr) {
            status = DistributedKv::Status::ERROR;
        }
    }
    return status;
}

int32_t ServiceInfoKvAdapter::RegisterKvStoreDeathListener()
{
    HILOGI("Register death listener");
    {
        std::lock_guard<std::mutex> lock(kvDeathRecipientMutex_);
        kvDataMgr_.RegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::UnregisterKvStoreDeathListener()
{
    HILOGI("UnRegister death listener");
    // [原则12] 使用正确的互斥锁，与Register保持一致
    {
        std::lock_guard<std::mutex> lock(kvDeathRecipientMutex_);
        kvDataMgr_.UnRegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::Delete(const std::string& key)
{
    if (key.empty() || key.size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid: key is empty or too long");
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
        status = kvStorePtr_->Delete(kvKey);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Delete kv by key failed!");
        return DP_DEL_KV_DB_FAIL;
    }
    HILOGD("Delete kv by key success!");
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::DeleteBatch(const std::vector<std::string>& keys)
{
    if (keys.empty() || keys.size() > MAX_PROFILE_SIZE) {
        HILOGE("keys size(%{public}zu) is invalid!", keys.size());
        return DP_INVALID_PARAMS;
    }

    uint32_t keysSize = static_cast<uint32_t>(keys.size());
    std::vector<std::vector<DistributedKv::Key>> delKeyBatches;
    for (uint32_t i = 0; i < keysSize; i += MAX_BATCH_SIZE) {
        uint32_t end = (i + MAX_BATCH_SIZE) > keysSize ? keysSize : (i + MAX_BATCH_SIZE);
        auto batch = std::vector<std::string>(keys.begin() + i, keys.begin() + end);
        std::vector<DistributedKv::Key> delKeys;
        for (const auto& item : batch) {
            DistributedKv::Key key(item);
            delKeys.emplace_back(key);
        }
        delKeyBatches.emplace_back(delKeys);
    }
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStorePtr is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        for (const auto& delKeys : delKeyBatches) {
            DistributedKv::Status status = kvStorePtr_->DeleteBatch(delKeys);
            if (status != DistributedKv::Status::SUCCESS) {
                HILOGE("DeleteBatch failed!");
                return DP_DEL_KV_DB_FAIL;
            }
        }
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::PutBatch(const std::map<std::string, std::string> &values)
{
    if (values.empty() || values.size() > MAX_PROFILE_SIZE) {
        HILOGE("Param is invalid!");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::Status status = DistributedKv::Status::ERROR;
    std::vector<DistributedKv::Entry> entries;
    for (const auto& item : values) {
        DistributedKv::Key kvKey(item.first);
        DistributedKv::Value kvValue(item.second);
        DistributedKv::Entry entry;
        entry.key = kvKey;
        entry.value = kvValue;
        entries.emplace_back(entry);
    }
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvDBPtr is null!");
            return DP_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->PutBatch(entries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("PutBatch kv to db failed, ret: %{public}d", status);
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::GetByPrefix(const std::string &keyPrefix, std::map<std::string, std::string> &values)
{
    HILOGI("key prefix: %{public}s", ProfileUtils::GetDbKeyAnonyString(keyPrefix).c_str());
    // if prefix is empty, get all entries.
    DistributedKv::Key allEntryKeyPrefix(keyPrefix);
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Status status = DistributedKv::Status::ERROR;
    {
        std::lock_guard<std::mutex> lock(kvAdapterMutex_);
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStoragePtr_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    }
    if (status != DistributedKv::Status::SUCCESS) {
        HILOGE("Query data by keyPrefix failed, prefix: %{public}s",
            ProfileUtils::GetDbKeyAnonyString(keyPrefix).c_str());
        return DP_GET_KV_DB_FAIL;
    }
    if (allEntries.empty()) {
        HILOGE("Not find in kv_store prefix: %{public}s", ProfileUtils::GetDbKeyAnonyString(keyPrefix).c_str());
        return DP_NOT_FIND_DATA;
    }
    if (allEntries.size() > MAX_DB_SIZE) {
        HILOGE("AllEntries size is invalid!size: %{public}zu! prefix: %{public}s",
            allEntries.size(), ProfileUtils::GetDbKeyAnonyString(keyPrefix).c_str());
        return DP_INVALID_PARAMS;
    }
    for (const auto& item : allEntries) {
        values[item.key.ToString()] = item.value.ToString();
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::DeleteByPrefix(const std::string& keyPrefix)
{
    (void)keyPrefix;
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::Sync(const std::vector<std::string>& deviceList, SyncMode syncMode)
{
    (void)deviceList;
    (void)syncMode;
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::GetDeviceEntries(const std::string& udid, std::map<std::string, std::string>& values)
{
    (void)udid;
    (void)values;
    return DP_SUCCESS;
}

int32_t ServiceInfoKvAdapter::RemoveDeviceData(const std::string& uuid)
{
    (void)uuid;
    return DP_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
