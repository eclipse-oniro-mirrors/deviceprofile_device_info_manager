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
 * @tc.desc: GetRDBPtr success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbAdapterTest, GetRDBPtr001, TestSize.Level1)
{
    std::lock_guard<std::mutex> lock(g_rdbAdapterTestMtx);
    store->UnInit();
    int32_t errCode = store->GetRDBPtr();
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
} // namespace DistributedDeviceProfile
} // namespace OHOS
