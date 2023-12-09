/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <mutex>
#include <chrono>
#include <unistd.h>
#include "rdb_adapter.h"
#include "rdb_errno.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std::chrono_literals;
namespace {
    const std::set<std::string> TABLES = {
        "trust_device_table",
        "accesser_table",
        "accessee_table",
        "access_control_table",
        "subscribe_trust_info_table"
    };
    const std::string TAG = "rdbAdapter";
}

RdbAdapter::RdbAdapter()
{
    HILOGI("rdbAdapter constructor");
}

RdbAdapter::~RdbAdapter()
{
    HILOGI("rdbAdapter destructor");
}

int32_t RdbAdapter::Init()
{
    int32_t retryTimes = RDB_INIT_MAX_TIMES;
    while (retryTimes > 0) {
        if (GetRDBPtr() == DP_SUCCESS) {
            HILOGI("rdbAdapter init success");
            return DP_SUCCESS;
        }
        usleep(RDB_INIT_INTERVAL_TIME);
        retryTimes--;
    }
    HILOGI("rdbAdapter init failed");
    return DP_RDBADAPTER_INIT_FAIL;
}

int32_t RdbAdapter::UnInit()
{
    HILOGI("rdbAdapter unInit ");
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        store_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Put(int64_t& outRowId, const std::string& table, const ValuesBucket& values)
{
    if (store_ == nullptr) {
        return DP_RDB_DB_PTR_NULL;
        HILOGI("RDBStore_ is null");
    }
    if (TABLES.find(table) == TABLES.end()) {
        HILOGI("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        if (store_->Insert(outRowId, table, values) != E_OK) {
            HILOGI("rdbAdapter put failed");
            return DP_RDBADAPTER_PUT_FAIL;
        };
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Delete(int32_t& deleteRows, const std::string& table, const std::string& whereClause,
    const std::vector<ValueObject>& bindArgs)
{
    if (store_ == nullptr) {
        return DP_RDB_DB_PTR_NULL;
        HILOGI("RDBStore_ is null");
    }
    if (TABLES.find(table) == TABLES.end()) {
        HILOGI("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        if (store_->Delete(deleteRows, table, whereClause, bindArgs) != E_OK) {
            HILOGI("rdbAdapter delete failed");
            return DP_RDBADAPTER_DELETE_FAIL;
        };
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Update(int32_t& changedRows, const std::string& table, const ValuesBucket& values,
    const std::string& whereClause, const std::vector<ValueObject>& bindArgs)
{
    if (store_ == nullptr) {
        return DP_RDB_DB_PTR_NULL;
        HILOGI("RDBStore_ is null");
    }
    if (TABLES.find(table) == TABLES.end()) {
        HILOGI("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        if (store_->Update(changedRows, table, values, whereClause, bindArgs) != E_OK) {
            HILOGI("rdbAdapter update failed");
            return DP_RDBADAPTER_UPDATE_FAIL;
        };
    }
    return DP_SUCCESS;
}

std::shared_ptr<ResultSet> RdbAdapter::Get(const std::string& sql, const std::vector<ValueObject>& args)
{
    std::shared_ptr<ResultSet> resultSet = nullptr;
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        resultSet = store_->QueryByStep(sql, args);
    }
    return resultSet;
}

int32_t RdbAdapter::GetRDBPtr()
{
    int32_t version = RDB_VERSION;
    OpenCallback helper;
    RdbStoreConfig config(RDB_PATH + DATABASE_NAME);
    int32_t errCode = E_OK;
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        store_ = RdbHelper::GetRdbStore(config, version, helper, errCode);
    }
    if (errCode != E_OK) {
        HILOGI("rdbAdapter getRDBPtr failed");
        return DP_GET_RDBSTORE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::CreateTable(const std::string& sql)
{
    if (store_ == nullptr) {
        return DP_RDB_DB_PTR_NULL;
        HILOGI("RDBStore_ is null");
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        if (store_->ExecuteSql(sql) != E_OK) {
            HILOGI("rdbAdapter create table failed");
            return DP_RDBADAPTER_CREATE_TABLE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::OnCreate(RdbStore& store_)
{
    HILOGI("rdbStore create");
    return NativeRdb::E_OK;
}

int32_t OpenCallback::OnUpgrade(RdbStore& store_, int oldVersion, int newVersion)
{
    HILOGI("rdbStore upgrade");
    return NativeRdb::E_OK;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
