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
#include "business_event_adapter.h"

#include <cinttypes>
#include <mutex>

#include "datetime_ex.h"
#include "string_ex.h"
#include "ffrt.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::DistributedKv;
namespace {
    constexpr int32_t MAX_INIT_RETRY_TIMES = 30;
    constexpr int32_t INIT_RETRY_SLEEP_INTERVAL = 200 * 1000;
    constexpr uint32_t MAX_BATCH_SIZE = 128;
    const std::string DATABASE_DIR = "/data/service/el1/public/database/distributed_device_profile_service";
    const std::string TAG = "BusinessEventAdapter";
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store_business";
}

BusinessEventAdapter::BusinessEventAdapter(
    const std::shared_ptr<DistributedKv::KvStoreDeathRecipient> &deathListener, DistributedKv::DataType dataType)
{
    this->deathRecipient_ = deathListener;
    this->dataType_ = dataType;
    HILOGD("BusinessEventAdapter Constructor Success");
}

int32_t BusinessEventAdapter::Init()
{
    HILOGI("Init local DB, dataType: %{public}d", static_cast<int32_t>(dataType_));
    if (isInited_.load()) {
        HILOGI("Local DB already inited.");
        return DP_SUCCESS;
    }
    this->appId_.appId = APP_ID;
    this->storeId_.storeId = STORE_ID;
    int32_t tryTimes = MAX_INIT_RETRY_TIMES;
    int64_t beginTime = GetTickCount();
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStorePtr();
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            HILOGI("Init KvStorePtr Success");
            RegisterKvStoreDeathListener();
            isInited_.store(true);
            return DP_SUCCESS;
        }
        HILOGI("CheckKvStore, left times: %{public}d, status: %{public}d", tryTimes, status);
        usleep(INIT_RETRY_SLEEP_INTERVAL);
        tryTimes--;
    }
    if (kvStorePtr_ == nullptr) {
        HILOGE("kvStorePtr is nullptr!");
        return DP_KV_DB_PTR_NULL;
    }
    isInited_.store(true);
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::UnInit()
{
    HILOGI("BusinessEventAdapter UnInit");
    if (isInited_.load()) {
        if (kvStorePtr_ == nullptr) {
            HILOGE("kvStorePtr is nullptr!");
            return DP_KV_DB_PTR_NULL;
        }
        UnregisterKvStoreDeathListener();
        kvStorePtr_.reset();
        isInited_.store(false);
    }
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::ReInit()
{
    HILOGI("BusinessEventAdapter ReInit");
    UnInit();
    return Init();
}

int32_t BusinessEventAdapter::Put(const std::string& key, const std::string& value)
{
    if (key.empty() || key.size() > MAX_STRING_LEN || value.empty() || value.size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid: key or value is empty or too long");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
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

int32_t BusinessEventAdapter::Get(const std::string& key, std::string& value)
{
    HILOGI("Get data by key: %{public}s", ProfileUtils::GetDbKeyAnonyString(key).c_str());
    DistributedKv::Key kvKey(key);
    DistributedKv::Value kvValue;
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
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

void BusinessEventAdapter::OnRemoteDied()
{
    HILOGI("OnRemoteDied, recover db begin");
    auto reInitTask = [this]() {
        HILOGI("ReInit, storeId:%{public}s", storeId_.storeId.c_str());
        ReInit();
    };
    ffrt::submit(reInitTask);
}

DistributedKv::Status BusinessEventAdapter::GetKvStorePtr()
{
    HILOGI("called");
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .area = 1,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .baseDir = DATABASE_DIR
    };
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
        status = kvDataMgr_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ == nullptr) {
            status = DistributedKv::Status::ERROR;
        }
    }
    return status;
}

int32_t BusinessEventAdapter::RegisterKvStoreDeathListener()
{
    HILOGI("Register death listener");
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
        kvDataMgr_.RegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::UnregisterKvStoreDeathListener()
{
    HILOGI("UnRegister death listener");
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
        kvDataMgr_.UnRegisterKvStoreServiceDeathRecipient(deathRecipient_);
    }
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::Delete(const std::string& key)
{
    HILOGI("key: %{public}s", ProfileUtils::GetDbKeyAnonyString(key).c_str());
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(BusinessAdapterMutex_);
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

int32_t BusinessEventAdapter::DeleteBatch(const std::vector<std::string>& keys)
{
    (void)keys;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::PutBatch(const std::map<std::string, std::string>& values)
{
    (void)values;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::GetByPrefix(const std::string& keyPrefix, std::map<std::string, std::string>& values)
{
    (void)keyPrefix;
    (void)values;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::DeleteByPrefix(const std::string& keyPrefix)
{
    (void)keyPrefix;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::Sync(const std::vector<std::string>& deviceList, SyncMode syncMode)
{
    (void)deviceList;
    (void)syncMode;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::GetDeviceEntries(const std::string& udid, std::map<std::string, std::string>& values)
{
    (void)udid;
    (void)values;
    return DP_SUCCESS;
}

int32_t BusinessEventAdapter::RemoveDeviceData(const std::string& uuid)
{
    (void)uuid;
    return DP_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
