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
#include <string>
#include <memory>
#include "gtest/gtest.h"
#include "rdb_adapter.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "result_set.h"
#include "rdb_open_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
    const std::string TAG = "rdbAdapterTest";
    const std::string SUCCESS_CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS trust_device_table\n"
            "(\n"
            "    deviceId     TEXT PRIMARY KEY,\n"
            "    deviceIdType INTEGER,\n"
            "    deviceIdHash TEXT,\n"
            "    status       INTEGER\n"
            ");";
    const std::string UN_SUCCESS_CREATE_TABLE_SQL = "NOT EXISTS \n"
            "(\n"
            "    deviceId     TEXT PRIMARY KEY,\n"
            "    deviceIdType INTEGER,\n"
            "    deviceIdHash TEXT,\n"
            "    status       INTEGER\n"
            ");";
    std::shared_ptr<RdbAdapter> store = nullptr;
    std::mutex g_rdbAdapterTestMtx;
}

class RdbAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbAdapterTest::SetUpTestCase(void)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store = std::make_shared<RdbAdapter>();
}

void RdbAdapterTest::TearDownTestCase(void)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->Init();
    store->CreateTable("DROP TABLE IF EXISTS trust_device_table");
    store->UnInit();
}

void RdbAdapterTest::SetUp()
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->Init();
    store->CreateTable("DROP TABLE IF EXISTS trust_device_table");
}

void RdbAdapterTest::TearDown()
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
}


/**
 * @tc.name:
 * @tc.desc: GetOldRDBPtr success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetOldRDBPtr001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION_5_1_2, RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
}


/**
 * @tc.name:
 * @tc.desc: Init success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Init001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/**
 * @tc.name:
 * @tc.desc: UnInit success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, UnInit001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    int32_t errCode = store->UnInit();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/**
 * @tc.name:
 * @tc.desc: CreateTable success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CreateTable001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    int32_t errCode = store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/**
 * @tc.name:
 * @tc.desc: CreateTable failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CreateTable002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    int32_t errCode = store->CreateTable(UN_SUCCESS_CREATE_TABLE_SQL);
    EXPECT_EQ(errCode, DP_RDBADAPTER_CREATE_TABLE_FAIL);
}

/**
 * @tc.name: CreateTable003
 * @tc.desc: CreateTable failed, RDBStore_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CreateTable003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    EXPECT_EQ(errCode, DP_RDB_DB_PTR_NULL);
    store->Init();
}

/**
 * @tc.name:
 * @tc.desc: Put Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
    EXPECT_EQ(outRowId, 1);
}

/**
 * @tc.name:
 * @tc.desc: Put table does not exist failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_xxxdevice_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_RDBADAPTER_TABLE_NOT_EXIST);
}

/**
 * @tc.name:
 * @tc.desc: Put failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId1 = 0;
    int64_t outRowId2 = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("222bbb"));
    value1.PutInt("status", 1);
    int32_t putErrCode1 = store->Put(outRowId1, table, value1);
    EXPECT_EQ(putErrCode1, DP_SUCCESS);
    EXPECT_EQ(outRowId1, 1);
    ValuesBucket value2;
    value2.Clear();
    value2.PutString("deviceId", std::string("111aaa"));
    value2.PutInt("deviceIdType", 3);
    value2.PutString("deviceIdHash", std::string("222bbb"));
    value2.PutInt("status", 1);
    int32_t putErrCode2 = store->Put(outRowId2, table, value2);
    EXPECT_EQ(putErrCode2, DP_RDBADAPTER_PUT_FAIL);
    EXPECT_EQ(outRowId2, 0);
}

/**
 * @tc.name: Put004
 * @tc.desc: Put failed, RDBStore_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    store->UnInit();
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_RDB_DB_PTR_NULL);
    store->Init();
}

/**
 * @tc.name:
 * @tc.desc: Delete success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t deleteErrCode = store->Delete(deleteRows, table, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_SUCCESS);
    EXPECT_EQ(deleteRows, 1);
}

/**
 * @tc.name:
 * @tc.desc: Delete table does not exist failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string deleteTable = "trust_xxxdevice_table";
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t deleteErrCode = store->Delete(deleteRows, deleteTable, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_RDBADAPTER_TABLE_NOT_EXIST);
}

/**
 * @tc.name:
 * @tc.desc: Delete failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string deleteTable = "trust_device_table";
    std::string whereClause = "xxxdeviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t deleteErrCode = store->Delete(deleteRows, deleteTable, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_RDBADAPTER_DELETE_FAIL);
}

/**
 * @tc.name: Delete004
 * @tc.desc: Delete failed, RDBStore_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("111aaa"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    store->UnInit();
    int32_t deleteErrCode = store->Delete(deleteRows, table, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_RDB_DB_PTR_NULL);
    store->Init();
}

/**
 * @tc.name:
 * @tc.desc: Update success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);
    ValuesBucket value2;
    value2.Clear();
    value2.PutString("deviceId", std::string("222bbb"));
    value2.PutInt("deviceIdType", 3);
    value2.PutString("deviceIdHash", std::string("abcdef"));
    value2.PutInt("status", 1);
    store->Put(outRowId, table, value2);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("111aaa"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", 2);

    int32_t changedRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_SUCCESS);
    std::shared_ptr<ResultSet> resultSet = store->Get("SELECT * FROM trust_device_table where deviceId = '111aaa'");
    resultSet->GoToFirstRow();
    RowEntity rowEntity;
    resultSet->GetRow(rowEntity);
    int32_t status = rowEntity.Get("status");
    EXPECT_EQ(status, 2);
}

/**
 * @tc.name:
 * @tc.desc: Update table does not exist failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("111aaa"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", 2);

    std::string failTable = "trust_xxxdevice_table";
    int32_t changedRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t updateErrCode = store->Update(changedRows, failTable, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_RDBADAPTER_TABLE_NOT_EXIST);
}

/**
 * @tc.name:
 * @tc.desc: Update failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("111aaa"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", 2);

    int32_t changedRows = 0;
    std::string whereClause = "xxxdeviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);

    EXPECT_EQ(updateErrCode, DP_RDBADAPTER_UPDATE_FAIL);
}

/**
 * @tc.name: Update004
 * @tc.desc: Update failed, RDBStore_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);
    ValuesBucket value2;
    value2.Clear();
    value2.PutString("deviceId", std::string("222bbb"));
    value2.PutInt("deviceIdType", 3);
    value2.PutString("deviceIdHash", std::string("abcdef"));
    value2.PutInt("status", 1);
    store->Put(outRowId, table, value2);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("111aaa"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", 2);

    int32_t changedRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("111aaa"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    store->UnInit();
    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_RDB_DB_PTR_NULL);
    store->Init();
}

/**
 * @tc.name:
 * @tc.desc: Get success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Get001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    std::shared_ptr<ResultSet> resultSet = store->Get("SELECT * FROM trust_device_table where deviceId = '111aaa'");
    EXPECT_NE(resultSet, nullptr);
}

/**
 * @tc.name: Get002
 * @tc.desc: Get failed, RDBStore_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Get002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("111aaa"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    store->UnInit();
    std::shared_ptr<ResultSet> resultSet = store->Get("SELECT * FROM trust_device_table where deviceId = '111aaa'");
    EXPECT_EQ(resultSet, nullptr);
    store->Init();
}

/**
 * @tc.name: ConnectDB001
 * @tc.desc: ConnectDB success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, ConnectDB001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->ConnectDB(rdbStore, RDB_VERSION_5_1_2, ACL_RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: ConnectDB002
 * @tc.desc: ConnectDB with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, ConnectDB002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->ConnectDB(rdbStore, RDB_VERSION_5_1_2, "/invalid/path/to/database.db");
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: CheckMigrateDB001
 * @tc.desc: CheckMigrateDB with no migration needed (old DB not exists)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CheckMigrateDB001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    int32_t errCode = store->CheckMigrateDB();
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: Init002
 * @tc.desc: Init success without migration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Init002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetRDBPtr002
 * @tc.desc: GetRDBPtr with ACL path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION_5_1_2, ACL_RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: GetRDBPtr003
 * @tc.desc: GetRDBPtr with invalid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION_5_1_2, "/invalid/nonexistent/path/db.db");
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: GetRDBPtr004
 * @tc.desc: GetRDBPtr with different DB version
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION_5_1, ACL_RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: GetRDBPtr005
 * @tc.desc: GetRDBPtr with RDB_VERSION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION, RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: GetRDBPtr006
 * @tc.desc: GetRDBPtr with empty path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr006, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->GetRDBPtr(rdbStore, RDB_VERSION_5_1_2, "");
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: ConnectDB003
 * @tc.desc: ConnectDB with old RDB path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, ConnectDB003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->ConnectDB(rdbStore, RDB_VERSION_5_1_2, RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: ConnectDB004
 * @tc.desc: ConnectDB with RDB_VERSION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, ConnectDB004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->ConnectDB(rdbStore, RDB_VERSION, RDB_PATH + DATABASE_NAME);
    EXPECT_EQ(errCode, DP_SUCCESS);
    EXPECT_NE(rdbStore, nullptr);
}

/**
 * @tc.name: ConnectDB005
 * @tc.desc: ConnectDB with empty path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, ConnectDB005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<RdbStore> rdbStore = nullptr;
    int32_t errCode = store->ConnectDB(rdbStore, RDB_VERSION_5_1_2, "");
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: Put005
 * @tc.desc: Put with empty deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string(""));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Put006
 * @tc.desc: Put with long deviceId string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put006, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    std::string longDeviceId(256, 'a');
    values.PutString("deviceId", longDeviceId);
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("222bbb"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Put007
 * @tc.desc: Put with zero deviceIdType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put007, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("test007"));
    values.PutInt("deviceIdType", 0);
    values.PutString("deviceIdHash", std::string("hash007"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Put008
 * @tc.desc: Put with negative deviceIdType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put008, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("test008"));
    values.PutInt("deviceIdType", -1);
    values.PutString("deviceIdHash", std::string("hash008"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Put009
 * @tc.desc: Put with max status value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Put009, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("test009"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("hash009"));
    values.PutInt("status", INT32_MAX);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Delete005
 * @tc.desc: Delete with empty where clause
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("delete005"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("hash005"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string whereClause = "";
    ValueObject valueObject(std::string("delete005"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t deleteErrCode = store->Delete(deleteRows, table, whereClause, bindArgs);
    EXPECT_NE(deleteErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Delete006
 * @tc.desc: Delete non-existent record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete006, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int32_t deleteRows = 0;
    std::string table = "trust_device_table";
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("nonexistent"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t deleteErrCode = store->Delete(deleteRows, table, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_SUCCESS);
    EXPECT_EQ(deleteRows, 0);
}

/**
 * @tc.name: Delete007
 * @tc.desc: Delete with empty bindArgs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Delete007, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("delete007"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("hash007"));
    values.PutInt("status", 1);
    store->Put(outRowId, table, values);

    int32_t deleteRows = 0;
    std::string whereClause = "deviceId = 'delete007'";
    const std::vector<ValueObject>& bindArgs = {};

    int32_t deleteErrCode = store->Delete(deleteRows, table, whereClause, bindArgs);
    EXPECT_EQ(deleteErrCode, DP_SUCCESS);
    EXPECT_EQ(deleteRows, 1);
}

/**
 * @tc.name: Update005
 * @tc.desc: Update non-existent record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    std::string table = "trust_device_table";

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("nonexistent"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("hash"));
    newValues.PutInt("status", 2);

    int32_t changedRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("nonexistent"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_SUCCESS);
    EXPECT_EQ(changedRows, 0);
}

/**
 * @tc.name: Update006
 * @tc.desc: Update with negative status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update006, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("update006"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("update006"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", -1);

    int32_t changedRows = 0;
    std::string whereClause = "deviceId = ?";
    ValueObject valueObject(std::string("update006"));
    const std::vector<ValueObject>& bindArgs = {valueObject};

    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_SUCCESS);
}

/**
 * @tc.name: Update007
 * @tc.desc: Update with empty bindArgs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Update007, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("update007"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    ValuesBucket newValues;
    newValues.Clear();
    newValues.PutString("deviceId", std::string("update007"));
    newValues.PutInt("deviceIdType", 3);
    newValues.PutString("deviceIdHash", std::string("222bbb"));
    newValues.PutInt("status", 2);

    int32_t changedRows = 0;
    std::string whereClause = "deviceId = 'update007'";
    const std::vector<ValueObject>& bindArgs = {};

    int32_t updateErrCode = store->Update(changedRows, table, newValues, whereClause, bindArgs);
    EXPECT_EQ(updateErrCode, DP_SUCCESS);
    EXPECT_EQ(changedRows, 1);
}

/**
 * @tc.name: Get003
 * @tc.desc: Get with empty SQL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Get003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    std::shared_ptr<ResultSet> resultSet = store->Get("");
    EXPECT_NE(resultSet, nullptr);
}

/**
 * @tc.name: Get004
 * @tc.desc: Get with non-matching query
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Get004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    std::shared_ptr<ResultSet> resultSet =
        store->Get("SELECT * FROM trust_device_table where deviceId = 'nonexistent'");
    EXPECT_NE(resultSet, nullptr);
}

/**
 * @tc.name: Get005
 * @tc.desc: Get with bindArgs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Get005, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket value1;
    value1.Clear();
    value1.PutString("deviceId", std::string("get005"));
    value1.PutInt("deviceIdType", 3);
    value1.PutString("deviceIdHash", std::string("abcdef"));
    value1.PutInt("status", 1);
    store->Put(outRowId, table, value1);

    std::string sql = "SELECT * FROM trust_device_table where deviceId = ?";
    ValueObject valueObject(std::string("get005"));
    const std::vector<ValueObject>& args = {valueObject};
    std::shared_ptr<ResultSet> resultSet = store->Get(sql, args);
    EXPECT_NE(resultSet, nullptr);
}

/**
 * @tc.name: Init003
 * @tc.desc: Init with ACL database path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, Init003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
    store->CreateTable(SUCCESS_CREATE_TABLE_SQL);
    int64_t outRowId = 0;
    std::string table = "trust_device_table";
    ValuesBucket values;
    values.Clear();
    values.PutString("deviceId", std::string("init003"));
    values.PutInt("deviceIdType", 3);
    values.PutString("deviceIdHash", std::string("hash003"));
    values.PutInt("status", 1);
    int32_t putErrCode = store->Put(outRowId, table, values);
    EXPECT_EQ(putErrCode, DP_SUCCESS);
}

/**
 * @tc.name: CreateTable004
 * @tc.desc: CreateTable with ACL path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CreateTable004, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    int32_t errCode = store->Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
    const std::string createTableSql = "CREATE TABLE IF NOT EXISTS test_table\n"
            "(\n"
            "    id     TEXT PRIMARY KEY,\n"
            "    value  INTEGER\n"
            ");";
    int32_t createErrCode = store->CreateTable(createTableSql);
    EXPECT_EQ(createErrCode, DP_SUCCESS);
    store->CreateTable("DROP TABLE IF EXISTS test_table");
}

/**
 * @tc.name: CheckMigrateDB002
 * @tc.desc: CheckMigrateDB after Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CheckMigrateDB002, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->Init();
    int32_t errCode = store->CheckMigrateDB();
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: CheckMigrateDB003
 * @tc.desc: CheckMigrateDB after UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, CheckMigrateDB003, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->CheckMigrateDB();
    EXPECT_NE(errCode, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
