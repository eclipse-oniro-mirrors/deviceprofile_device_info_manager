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

#include "service_info_rdb_adapter.h"

#include <mutex>
#include <chrono>
#include <unistd.h>

#include "distributed_device_profile_constants.h"
#include "dp_services_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "rdb_errno.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoRdbAdapter);
using namespace std::chrono_literals;
namespace {
    const std::set<std::string> TABLES = {
        "service_info_profile"
    };
    const std::string TAG = "ServiceInfoRdbAdapter";
}

int32_t ServiceInfoRdbAdapter::Init()
{
    int32_t retryTimes = RDB_INIT_MAX_TIMES;
    while (retryTimes > 0) {
        if (GetRDBPtr() == DP_SUCCESS) {
            HILOGI("ServiceInfoRdbAdapter init success");
            return DP_SUCCESS;
        }
        usleep(RDB_INIT_INTERVAL_TIME);
        retryTimes--;
    }
    HILOGE("ServiceInfoRdbAdapter init failed");
    return DP_RDBADAPTER_INIT_FAIL;
}

int32_t ServiceInfoRdbAdapter::UnInit()
{
    HILOGI("ServiceInfoRdbAdapter unInit");
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        store_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoRdbAdapter::Put(int64_t& outRowId, const std::string& table, const ValuesBucket& values)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        int32_t ret = store_->Insert(outRowId, table, values);
        if (ret == E_SQLITE_CORRUPT) {
            HILOGE("database corrupt ret:%{public}d", ret);
            int32_t restoreRet = store_->Restore("");
            if (restoreRet != E_OK) {
                HILOGE("Restore failed restoreRet:%{public}d", restoreRet);
                return DP_RDB_DATABASE_RESTORE_FAIL;
            }
            ret = store_->Insert(outRowId, table, values);
        }
        if (ret != E_OK) {
            HILOGE("ServiceInfoRdbAdapter put failed ret:%{public}d", ret);
            return DP_RDBADAPTER_PUT_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoRdbAdapter::Delete(int32_t& deleteRows, const std::string& table, const std::string& whereClause,
    const std::vector<ValueObject>& bindArgs)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        int32_t ret = store_->Delete(deleteRows, table, whereClause, bindArgs);
        if (ret == E_SQLITE_CORRUPT) {
            HILOGE("database corrupt ret:%{public}d", ret);
            int32_t restoreRet = store_->Restore("");
            if (restoreRet != E_OK) {
                HILOGE("Restore failed restoreRet:%{public}d", restoreRet);
                return DP_RDB_DATABASE_RESTORE_FAIL;
            }
            ret = store_->Delete(deleteRows, table, whereClause, bindArgs);
        }
        if (ret != E_OK) {
            HILOGE("ServiceInfoRdbAdapter delete failed ret:%{public}d", ret);
            return DP_RDBADAPTER_DELETE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoRdbAdapter::Update(int32_t& changedRows, const std::string& table, const ValuesBucket& values,
    const std::string& whereClause, const std::vector<ValueObject>& bindArgs)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        int32_t ret = store_->Update(changedRows, table, values, whereClause, bindArgs);
        if (ret == E_SQLITE_CORRUPT) {
            HILOGE("database corrupt ret:%{public}d", ret);
            int32_t restoreRet = store_->Restore("");
            if (restoreRet != E_OK) {
                HILOGE("Restore failed restoreRet:%{public}d", restoreRet);
                return DP_RDB_DATABASE_RESTORE_FAIL;
            }
            ret = store_->Update(changedRows, table, values, whereClause, bindArgs);
        }
        if (ret != E_OK) {
            HILOGE("ServiceInfoRdbAdapter update failed ret:%{public}d", ret);
            return DP_RDBADAPTER_UPDATE_FAIL;
        }
    }
    return DP_SUCCESS;
}

std::shared_ptr<ResultSet> ServiceInfoRdbAdapter::Get(const std::string& sql, const std::vector<ValueObject>& args)
{
    std::shared_ptr<ResultSet> resultSet = nullptr;
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return nullptr;
        }
        resultSet = store_->QueryByStep(sql, args);
        if (resultSet == nullptr) {
            HILOGE("resultSet is null");
            return nullptr;
        }
        int32_t rowCount = ROWCOUNT_INIT;
        int32_t ret = resultSet->GetRowCount(rowCount);
        if (ret == E_SQLITE_CORRUPT) {
            HILOGE("database corrupt ret:%{public}d", ret);
            resultSet->Close();
            ret = store_->Restore("");
            if (ret != E_OK) {
                HILOGE("Restore failed ret:%{public}d", ret);
                return nullptr;
            }
            resultSet = store_->QueryByStep(sql, args);
        }
    }
    return resultSet;
}

int32_t ServiceInfoRdbAdapter::GetRDBPtr()
{
    int32_t version = RDB_VERSION;
    ServiceInfoOpenCallback helper;
    RdbStoreConfig config(SERVICE_INFO_PROFILE_RDB_PATH + SERVICE_INFO_PROFILE_DATABASE_NAME);
    config.SetSecurityLevel(SecurityLevel::S2);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    int32_t errCode = E_OK;
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        store_ = RdbHelper::GetRdbStore(config, version, helper, errCode);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        NativeRdb::RebuiltType rebuiltType = NativeRdb::RebuiltType::NONE;
        errCode = store_->GetRebuilt(rebuiltType);
        if (errCode != E_OK) {
            HILOGE("getRDBPtr failed errCode:%{public}d", errCode);
            return DP_GET_RDBSTORE_FAIL;
        }
        if (rebuiltType == NativeRdb::RebuiltType::REBUILT) {
            HILOGE("database corrupt");
            int32_t restoreRet = store_->Restore("");
            if (restoreRet != E_OK) {
                HILOGE("Restore failed restoreRet:%{public}d", restoreRet);
                return DP_RDB_DATABASE_RESTORE_FAIL;
            }
        }
    }
    return DP_SUCCESS;
}

bool ServiceInfoRdbAdapter::IsInit()
{
    std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
    if (store_ == nullptr) {
        return false;
    }
    return true;
}

int32_t ServiceInfoRdbAdapter::CreateTable(const std::string& sql)
{
    {
        std::lock_guard<std::mutex> lock(ServiceInfoRdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        if (store_->ExecuteSql(sql) != E_OK) {
            HILOGE("ServiceInfoRdbAdapter create table failed");
            return DP_RDBADAPTER_TABLE_NOT_EXIST;
        }
    }
    return DP_SUCCESS;
}

int32_t ServiceInfoOpenCallback::OnCreate(RdbStore& store)
{
    HILOGI("rdbStore create");
    return NativeRdb::E_OK;
}

int32_t ServiceInfoOpenCallback::OnUpgrade(RdbStore& store, int oldVersion, int newVersion)
{
    HILOGI("rdbStore upgrade");
    return NativeRdb::E_OK;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
