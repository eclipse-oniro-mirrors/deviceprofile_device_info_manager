/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
    HILOGE("rdbAdapter init failed");
    return DP_RDBADAPTER_INIT_FAIL;
}

int32_t RdbAdapter::UnInit()
{
    HILOGI("rdbAdapter unInit");
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        store_ = nullptr;
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Put(int64_t& outRowId, const std::string& table, const ValuesBucket& values)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
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
            HILOGE("rdbAdapter put failed ret:%{public}d", ret);
            return DP_RDBADAPTER_PUT_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Delete(int32_t& deleteRows, const std::string& table, const std::string& whereClause,
    const std::vector<ValueObject>& bindArgs)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
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
            HILOGE("rdbAdapter delete failed ret:%{public}d", ret);
            return DP_RDBADAPTER_DELETE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t RdbAdapter::Update(int32_t& changedRows, const std::string& table, const ValuesBucket& values,
    const std::string& whereClause, const std::vector<ValueObject>& bindArgs)
{
    if (TABLES.find(table) == TABLES.end()) {
        HILOGE("table does not exist");
        return DP_RDBADAPTER_TABLE_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
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
            HILOGE("rdbAdapter update failed ret:%{public}d", ret);
            return DP_RDBADAPTER_UPDATE_FAIL;
        }
    }
    return DP_SUCCESS;
}

std::shared_ptr<ResultSet> RdbAdapter::Get(const std::string& sql, const std::vector<ValueObject>& args)
{
    std::shared_ptr<ResultSet> resultSet = nullptr;
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
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

int32_t RdbAdapter::GetRDBPtr()
{
    int32_t version = RDB_VERSION_5_1_2;
    OpenCallback helper;
    RdbStoreConfig config(RDB_PATH + DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    int32_t errCode = E_OK;
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
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

int32_t RdbAdapter::CreateTable(const std::string& sql)
{
    {
        std::lock_guard<std::mutex> lock(rdbAdapterMtx_);
        if (store_ == nullptr) {
            HILOGE("RDBStore_ is null");
            return DP_RDB_DB_PTR_NULL;
        }
        if (store_->ExecuteSql(sql) != E_OK) {
            HILOGE("rdbAdapter create table failed");
            return DP_RDBADAPTER_CREATE_TABLE_FAIL;
        }
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::OnCreate(RdbStore& store)
{
    HILOGI("rdbStore create");
    if (CreateTable(store) != DP_SUCCESS) {
        HILOGE("CreateTable failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (CreateUniqueIndex(store) != DP_SUCCESS) {
        HILOGE("CreateUniqueIndex failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::OnUpgrade(RdbStore& store, int oldVersion, int newVersion)
{
    HILOGI("rdbStore upgrade, oldVersion : %{public}d, newVersion : %{public}d", oldVersion, newVersion);
    if (oldVersion == RDB_VERSION && newVersion == RDB_VERSION_5_1) {
        UpgradeVersionOneToTwo(store);
    }
    if (oldVersion == RDB_VERSION_5_1 && newVersion == RDB_VERSION_5_1_2) {
        UpgradeVersionTwoToThree(store);
    }
    if (oldVersion == RDB_VERSION && newVersion == RDB_VERSION_5_1_2) {
        UpgradeVersionOneToTwo(store);
        UpgradeVersionTwoToThree(store);
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::CreateTable(RdbStore& store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(CREATE_TURST_DEVICE_TABLE_SQL) != NativeRdb::E_OK) {
        HILOGE("trust_device_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESS_CONTROL_TABLE_SQL) != NativeRdb::E_OK) {
        HILOGE("access_control_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSER_TABLE_SQL) != NativeRdb::E_OK) {
        HILOGE("accesser_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSEE_TABLE_SQL) != NativeRdb::E_OK) {
        HILOGE("accessee_table create failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::CreateUniqueIndex(RdbStore& store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(CREATE_TURST_DEVICE_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("trust_device_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESS_CONTROL_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("access_control_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSER_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("accesser_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("accessee_table unique index create failed");
        return DP_CREATE_UNIQUE_INDEX_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::UpgradeVersionOneToTwo(RdbStore& store)
{
    int32_t ret = AddAcerColumnOneToTwo(store);
    if (ret != DP_SUCCESS) {
        HILOGE("AddAcerColumn failed");
        return ret;
    }
    ret = AddAceeColumnOneToTwo(store);
    if (ret != DP_SUCCESS) {
        HILOGE("AddAceeColumn failed");
        return ret;
    }
    ret = DropAndRebuildIndex(store);
    if (ret != DP_SUCCESS) {
        HILOGE("DropAndRebuildIndex failed");
        return ret;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::UpgradeVersionTwoToThree(RdbStore &store)
{
    int32_t ret = AddAclColumnTwoToThree(store);
    if (ret != DP_SUCCESS) {
        HILOGE("AddAclColumnTwoToThree failed");
        return ret;
    }
    ret = AddAcerColumnTwoToThree(store);
    if (ret != DP_SUCCESS) {
        HILOGE("AddAcerColumnTwoToThree failed");
        return ret;
    }
    ret = AddAceeColumnTwoToThree(store);
    if (ret != DP_SUCCESS) {
        HILOGE("AddAceeColumnTwoToThree failed");
        return ret;
    }
    ret = DropAndRebuildIndex(store);
    if (ret != DP_SUCCESS) {
        HILOGE("DropAndRebuildIndex failed");
        return ret;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::AddAcerColumnOneToTwo(RdbStore& store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_DEVICE_NAME) != NativeRdb::E_OK) {
        HILOGE("add column accesserDeviceName to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_SERVICE_NAME) != NativeRdb::E_OK) {
        HILOGE("add column accesserServiceName to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID) != NativeRdb::E_OK) {
        HILOGE("add column accesserCredentialId to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_STATUS) != NativeRdb::E_OK) {
        HILOGE("add column accesserStatus to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_ID) != NativeRdb::E_OK) {
        HILOGE("add column accesserSessionKeyId to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_SESSION_KEY_TIMESTAMP) != NativeRdb::E_OK) {
        HILOGE("add column accesserSessionKeyTimeStamp to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::AddAceeColumnOneToTwo(RdbStore &store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_DEVICE_NAME) != NativeRdb::E_OK) {
        HILOGE("add column accesseeDeviceName to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SERVICE_NAME) != NativeRdb::E_OK) {
        HILOGE("add column accesseeServiceName to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID) != NativeRdb::E_OK) {
        HILOGE("add column accesseeCredentialId to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_STATUS) != NativeRdb::E_OK) {
        HILOGE("add column accesseeStatus to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_ID) != NativeRdb::E_OK) {
        HILOGE("add column accesseeSessionKeyId to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_SESSION_KEY_TIMESTAMP) != NativeRdb::E_OK) {
        HILOGE("add column accesseeSessionKeyTimeStamp to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::AddAclColumnTwoToThree(RdbStore &store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(ALTER_TABLE_ACCESS_CONTROL_ADD_COLUMN_EXTRA_DATA) != NativeRdb::E_OK) {
        HILOGE("add column extraData to acL table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::AddAcerColumnTwoToThree(RdbStore &store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_CREDENTIAL_ID_STR) != NativeRdb::E_OK) {
        HILOGE("add column accesserCredentialIdStr to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACER_ADD_COLUMN_ACER_EXTRA_DATA) != NativeRdb::E_OK) {
        HILOGE("add column accesserExtraData to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::AddAceeColumnTwoToThree(RdbStore &store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_CREDENTIAL_ID_STR) != NativeRdb::E_OK) {
        HILOGE("add column accesseeCredentialIdStr to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(ALTER_TABLE_ACEE_ADD_COLUMN_ACEE_EXTRA_DATA) != NativeRdb::E_OK) {
        HILOGE("add column accesseeExtraData to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t OpenCallback::DropAndRebuildIndex(RdbStore& store)
{
    std::lock_guard<std::mutex> lock(rdbStoreMtx_);
    if (store.ExecuteSql(DROP_OLD_UNIQUE_INDEX_ON_ACER) != NativeRdb::E_OK) {
        HILOGE("delete old unique index to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(DROP_OLD_UNIQUE_INDEX_ON_ACEE) != NativeRdb::E_OK) {
        HILOGE("delete old unique index to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSER_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("create new unique index to acer table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    if (store.ExecuteSql(CREATE_ACCESSEE_TABLE_UNIQUE_INDEX_SQL) != NativeRdb::E_OK) {
        HILOGE("create new unique index to acee table failed");
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
