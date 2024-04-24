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

#define private   public
#define protected public
#include <string>
#include <vector>
#include <memory>
#include "gtest/gtest.h"
#include "refbase.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "ikv_adapter.h"
#include "kv_adapter.h"
#include "kv_data_change_listener.h"
#include "kv_sync_completed_listener.h"
#include "kv_store_death_recipient.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

namespace {
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store";
    shared_ptr<IKVAdapter> kvStore = nullptr;
}

class KVAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void KVAdapterTest::SetUpTestCase(void)
{
    kvStore = make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
}

void KVAdapterTest::TearDownTestCase(void) {
}

void KVAdapterTest::SetUp()
{
    kvStore->Init();
}

void KVAdapterTest::TearDown()
{
    kvStore->UnInit();
}

/**
 * @tc.name: Init001
 * @tc.desc: Init succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Init001, TestSize.Level1)
{
    kvStore->UnInit();
    EXPECT_EQ(DP_SUCCESS, kvStore->Init());
}

/**
 * @tc.name: UnInit001
 * @tc.desc: UnInit succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, UnInit001, TestSize.Level1)
{
    EXPECT_EQ(DP_SUCCESS, kvStore->UnInit());
}

/**
 * @tc.name: Put001
 * @tc.desc: Put succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put001, TestSize.Level1)
{
    EXPECT_EQ(DP_SUCCESS, kvStore->Put("key1", "value1"));
}

/**
 * @tc.name: Put002
 * @tc.desc: Put failed, Param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put002, TestSize.Level1)
{
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put("", "value1"));
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put("key1", ""));
}

/**
 * @tc.name: Put003
 * @tc.desc: Put failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put003, TestSize.Level1)
{
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Put("key1", "value1"));
}

/**
 * @tc.name: Put004
 * @tc.desc: Put first if.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Put004, TestSize.Level1)
{
    string key = "key";
    string value = "value";
    EXPECT_EQ(DP_SUCCESS, kvStore->Put(key, value));

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        value += 'a';
    }
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put(key, value));
    
    value = "";
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put(key, value));

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        key += 'a';
    }
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put(key, value));
    
    key = "";
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put(key, value));
}

/**
 * @tc.name: PutBatch001
 * @tc.desc: PutBatch succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch001, TestSize.Level1)
{
    map<string, string> values;
    values.insert(pair<string, string>("key2", "value2"));
    values.insert(pair<string, string>("key3", "value3"));
    EXPECT_EQ(DP_SUCCESS, kvStore->PutBatch(values));
}

/**
 * @tc.name: PutBatch002
 * @tc.desc: PutBatch failed, Param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch002, TestSize.Level1)
{
    map<string, string> values;
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->PutBatch(values));
    
    for (int32_t i = 0; i< MAX_PROFILE_SIZE + 5; i++) {
        values[to_string(i)] = "value";
    }
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->PutBatch(values));
}

/**
 * @tc.name: PutBatch003
 * @tc.desc: PutBatch failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, PutBatch003, TestSize.Level1)
{
    map<string, string> values;
    values.insert(pair<string, string>("key1", "value1"));
    values.insert(pair<string, string>("key2", "value2"));
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->PutBatch(values));
}

/**
 * @tc.name: Delete001
 * @tc.desc: Delete succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Delete001, TestSize.Level1)
{
    kvStore->Put("key4", "value4");
    EXPECT_EQ(DP_SUCCESS, kvStore->Delete("key4"));
}

/**
 * @tc.name: Delete002
 * @tc.desc: Delete failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Delete002, TestSize.Level1)
{
    kvStore->Put("key5", "value5");
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Delete("key5"));
}

/**
 * @tc.name: DeleteByPrefix001
 * @tc.desc: DeleteByPrefix succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix001, TestSize.Level1)
{
    kvStore->Put("key6", "value6");
    kvStore->Put("key7", "value7");
    EXPECT_EQ(DP_SUCCESS, kvStore->DeleteByPrefix("key"));
}

/**
 * @tc.name: DeleteByPrefix002
 * @tc.desc: DeleteByPrefix failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteByPrefix002, TestSize.Level1)
{
    kvStore->Put("key8", "value8");
    kvStore->Put("key9", "value9");
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->DeleteByPrefix("key"));
}

/**
 * @tc.name: Get001
 * @tc.desc: Get succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get001, TestSize.Level1)
{
    kvStore->Put("key10", "value10");
    string value;
    EXPECT_EQ(DP_SUCCESS, kvStore->Get("key10", value));
    EXPECT_EQ("value10", value);
}

/**
 * @tc.name: Get002
 * @tc.desc: Get failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get002, TestSize.Level1)
{
    kvStore->Put("key11", "value11");
    kvStore->UnInit();
    string value;
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Get("key11", value));
}

/**
 * @tc.name: GetByPrefix001
 * @tc.desc: GetByPrefix succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, GetByPrefix001, TestSize.Level1)
{
    kvStore->Put("GetByPrefix001a", "value");
    kvStore->Put("GetByPrefix001b", "value");
    map<string, string> values;
    EXPECT_EQ(DP_SUCCESS, kvStore->GetByPrefix("GetByPrefix001", values));
    EXPECT_EQ(2, values.size());
}

/**
 * @tc.name: GetByPrefix002
 * @tc.desc: GetByPrefix failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, GetByPrefix002, TestSize.Level1)
{
    kvStore->Put("GetByPrefix002a", "value");
    kvStore->Put("GetByPrefix002b", "value");
    kvStore->UnInit();
    map<string, string> values;
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->GetByPrefix("GetByPrefix002", values));
}

/**
 * @tc.name: GetByPrefix003
 * @tc.desc: GetByPrefix failed, AllEntries size is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, GetByPrefix003, TestSize.Level1)
{
    map<string, string> values;
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->GetByPrefix("GetByPrefix003", values));
}

/**
 * @tc.name: Sync001
 * @tc.desc: Sync failed, kvStorePtr is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Sync001, TestSize.Level1)
{
    kvStore->UnInit();
    vector<string> deviceList;
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Sync(deviceList, SyncMode::PUSH));
}

/**
 * @tc.name: Sync002
 * @tc.desc: Sync failed, deviceList is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Sync002, TestSize.Level1)
{
    vector<string> deviceList;
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Sync(deviceList, SyncMode::PUSH));
    
    for (int32_t i = 0; i < MAX_DEVICE_SIZE + 5; i++) {
        deviceList.emplace_back("deviceId");
    }
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Sync(deviceList, SyncMode::PUSH));
}

/**
 * @tc.name: Sync003
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Sync003, TestSize.Level1)
{
    vector<string> deviceList;
    deviceList.emplace_back("deviceId");
    SyncMode mode = SyncMode::PUSH;
    kvStore->Sync(deviceList, mode);
    
    mode = SyncMode::MAX;
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Sync(deviceList, mode));
    
    mode = SyncMode::MIN;
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Sync(deviceList, mode));
}

/**
 * @tc.name: DeleteKvStore001
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, DeleteKvStore001, TestSize.Level1)
{
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    int32_t ret = kvStore_->DeleteKvStore();
    EXPECT_EQ(DP_SUCCESS, ret);
}

/**
 * @tc.name: Get003
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get003, TestSize.Level1)
{
    std::string udid = "";
    std::string key = "";
    std::string value = "";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    int32_t ret = kvStore_->Get(udid, key, value);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

/**
 * @tc.name: Get004
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get004, TestSize.Level1)
{
    std::string udid = "11111";
    std::string key = "";
    std::string value = "";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    int32_t ret = kvStore_->Get(udid, key, value);;
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

/**
 * @tc.name: Get005
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get005, TestSize.Level1)
{
    std::string udid = "";
    std::string key = "11111";
    std::string value = "";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    int32_t ret = kvStore_->Get(udid, key, value);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

/**
 * @tc.name: Get006
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, Get006, TestSize.Level1)
{
    std::string udid = "11111";
    std::string key = "11111";
    std::string value = "";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    int32_t ret = kvStore_->Get(udid, key, value);
    EXPECT_EQ(DP_KV_DB_PTR_NULL, ret);
}

/**
 * @tc.name: SyncDeviceProfile001
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, SyncDeviceProfile001, TestSize.Level1)
{
    std::string udid = "11111";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    kvStore_->SyncDeviceProfile(udid);
}

/**
 * @tc.name: SyncDeviceProfile002
 * @tc.desc: syncMode all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KVAdapterTest, SyncDeviceProfile002, TestSize.Level1)
{
    std::string udid = "";
    shared_ptr<KVAdapter> kvStore_;
    kvStore_= make_shared<KVAdapter>(APP_ID, STORE_ID,
            make_shared<KvDataChangeListener>(),
            make_shared<KvSyncCompletedListener>(),
            make_shared<KvDeathRecipient>());
    kvStore_->SyncDeviceProfile(udid);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
