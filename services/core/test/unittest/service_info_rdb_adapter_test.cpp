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

#include "service_info_rdb_adapter.h"

#include <unistd.h>

#include <cstdlib>
#include <memory>
#include <string>

#include "distributed_device_profile_errors.h"
#include "gtest/gtest.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store_config.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace NativeRdb;
namespace {
constexpr int32_t DB_VERSION = 1;
constexpr int64_t UNCHANGED_ROW = -1;
constexpr int32_t UNCHANGED_COUNT = -1;
constexpr int32_t ONE_ROW = 1;
const std::string TABLE_NAME = "service_info_profile";
const std::string CREATE_SQL = "CREATE TABLE service_info_profile (id INTEGER PRIMARY KEY, value TEXT)";
}  // namespace
class ServiceInfoRdbAdapterFileTest : public testing::Test {
public:
    void SetUp() override
    {
        ASSERT_EQ(ServiceInfoRdbAdapter::GetInstance().UnInit(), DP_SUCCESS);
        char directory[] = "/data/local/tmp/dp_rdb_file_test_XXXXXX";
        const char *created = mkdtemp(directory);
        ASSERT_NE(created, nullptr);
        directory_ = created;
        databasePath_ = directory_ + "/memory.db";
    }
    void TearDown() override
    {
        EXPECT_EQ(ServiceInfoRdbAdapter::GetInstance().UnInit(), DP_SUCCESS);
        if (!directory_.empty()) {
            RdbStoreConfig config(databasePath_);
            config.SetStorageMode(StorageMode::MODE_MEMORY);
            EXPECT_EQ(RdbHelper::DeleteRdbStore(config), E_OK);
            EXPECT_EQ(rmdir(directory_.c_str()), 0);
        }
    }

protected:
    std::string directory_;
    std::string databasePath_;
    void OpenMemoryStore()
    {
        // This fixture never calls Init/GetRDBPtr, which use the service's persistent database path.
        RdbStoreConfig config(databasePath_);
        config.SetStorageMode(StorageMode::MODE_MEMORY);
        ServiceInfoOpenCallback callback;
        int32_t error = E_OK;
        auto store = RdbHelper::GetRdbStore(config, DB_VERSION, callback, error);
        ASSERT_EQ(error, E_OK);
        ASSERT_NE(store, nullptr);
        ServiceInfoRdbAdapter::GetInstance().store_ = store;
    }
};

/**
 * @tc.name: UnInitIsIdempotentAndClearsReadiness_001
 * @tc.desc: Verify that un init is idempotent and clears readiness.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, UnInitIsIdempotentAndClearsReadiness_001, TestSize.Level1)
{
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    EXPECT_FALSE(adapter.IsInit());
    EXPECT_EQ(adapter.UnInit(), DP_SUCCESS);
    EXPECT_EQ(adapter.UnInit(), DP_SUCCESS);
    EXPECT_FALSE(adapter.IsInit());
}

/**
 * @tc.name: InvalidTableIsRejectedBeforeStoreAccess_002
 * @tc.desc: Verify that invalid table is rejected before store access.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, InvalidTableIsRejectedBeforeStoreAccess_002, TestSize.Level1)
{
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    ValuesBucket values;
    int64_t row = UNCHANGED_ROW;
    int32_t count = UNCHANGED_COUNT;
    EXPECT_EQ(adapter.Put(row, "not_a_profile_table", values), DP_RDBADAPTER_TABLE_NOT_EXIST);
    EXPECT_EQ(adapter.Update(count, "not_a_profile_table", values, ""), DP_RDBADAPTER_TABLE_NOT_EXIST);
    EXPECT_EQ(adapter.Delete(count, "not_a_profile_table", ""), DP_RDBADAPTER_TABLE_NOT_EXIST);
    EXPECT_EQ(row, UNCHANGED_ROW);
    EXPECT_EQ(count, UNCHANGED_COUNT);
}

/**
 * @tc.name: MissingStoreRejectsValidTableOperations_002
 * @tc.desc: Verify that missing store rejects valid table operations.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, MissingStoreRejectsValidTableOperations_002, TestSize.Level1)
{
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    ValuesBucket values;
    int64_t row = UNCHANGED_ROW;
    int32_t count = UNCHANGED_COUNT;
    EXPECT_EQ(adapter.Put(row, TABLE_NAME, values), DP_RDB_DB_PTR_NULL);
    EXPECT_EQ(adapter.Update(count, TABLE_NAME, values, ""), DP_RDB_DB_PTR_NULL);
    EXPECT_EQ(adapter.Delete(count, TABLE_NAME, ""), DP_RDB_DB_PTR_NULL);
    EXPECT_EQ(adapter.CreateTable(CREATE_SQL), DP_RDB_DB_PTR_NULL);
    EXPECT_EQ(adapter.Get("SELECT * FROM service_info_profile"), nullptr);
    EXPECT_EQ(row, UNCHANGED_ROW);
    EXPECT_EQ(count, UNCHANGED_COUNT);
}

/**
 * @tc.name: MemoryStoreSupportsCreatePutReadUpdateAndDelete_001
 * @tc.desc: Verify that memory store supports create put read update and delete.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, MemoryStoreSupportsCreatePutReadUpdateAndDelete_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(OpenMemoryStore());
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    ASSERT_TRUE(adapter.IsInit());
    ASSERT_EQ(adapter.CreateTable(CREATE_SQL), DP_SUCCESS);
    ValuesBucket values;
    values.PutString("value", "before");
    int64_t row = UNCHANGED_ROW;
    ASSERT_EQ(adapter.Put(row, TABLE_NAME, values), DP_SUCCESS);
    EXPECT_GT(row, 0);
    int32_t changed = 0;
    ValuesBucket replacement;
    replacement.PutString("value", "after");
    ASSERT_EQ(adapter.Update(changed, TABLE_NAME, replacement, "id = ?", {ValueObject(row)}), DP_SUCCESS);
    EXPECT_EQ(changed, ONE_ROW);
    auto result = adapter.Get("SELECT value FROM service_info_profile WHERE id = ?", {ValueObject(row)});
    ASSERT_NE(result, nullptr);
    int32_t rowCount = 0;
    EXPECT_EQ(result->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, ONE_ROW);
    EXPECT_EQ(result->GoToFirstRow(), E_OK);
    std::string value;
    EXPECT_EQ(result->GetString(0, value), E_OK);
    EXPECT_EQ(value, "after");
    EXPECT_EQ(result->Close(), E_OK);
    EXPECT_EQ(adapter.Delete(changed, TABLE_NAME, "id = ?", {ValueObject(row)}), DP_SUCCESS);
    EXPECT_EQ(changed, ONE_ROW);
}

/**
 * @tc.name: SqlFailureMapsToAdapterErrors_002
 * @tc.desc: Verify that sql failure maps to adapter errors.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, SqlFailureMapsToAdapterErrors_002, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(OpenMemoryStore());
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    EXPECT_EQ(adapter.CreateTable("not valid sql"), DP_RDBADAPTER_TABLE_NOT_EXIST);
    ValuesBucket values;
    values.PutString("value", "test");
    int64_t row = UNCHANGED_ROW;
    int32_t count = UNCHANGED_COUNT;
    EXPECT_EQ(adapter.Put(row, TABLE_NAME, values), DP_RDBADAPTER_PUT_FAIL);
    EXPECT_EQ(adapter.Update(count, TABLE_NAME, values, ""), DP_RDBADAPTER_UPDATE_FAIL);
    EXPECT_EQ(adapter.Delete(count, TABLE_NAME, ""), DP_RDBADAPTER_DELETE_FAIL);
}

/**
 * @tc.name: OpenCallbacksDoNotCreateBusinessTables_001
 * @tc.desc: Verify that open callbacks do not create business tables.
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoRdbAdapterFileTest, OpenCallbacksDoNotCreateBusinessTables_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(OpenMemoryStore());
    auto &adapter = ServiceInfoRdbAdapter::GetInstance();
    ServiceInfoOpenCallback callback;
    ASSERT_NE(adapter.store_, nullptr);
    EXPECT_EQ(callback.OnCreate(*adapter.store_), E_OK);
    EXPECT_EQ(callback.OnUpgrade(*adapter.store_, DB_VERSION, DB_VERSION + 1), E_OK);
    EXPECT_EQ(adapter.CreateTable(CREATE_SQL), DP_SUCCESS);
    EXPECT_EQ(adapter.UnInit(), DP_SUCCESS);
    EXPECT_FALSE(adapter.IsInit());
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
