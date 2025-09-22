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

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "service_info_kv_adapter.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
using namespace OHOS::DistributedKv;
 
namespace {
    const std::string TEST_KEY = "test_key";
    const std::string TEST_VALUE = "test_value";
    const std::string TEST_KEY_PREFIX = "test_prefix";
    const std::string TEST_DEVICE_ID = "test_device_id";
    const std::string TEST_UUID = "test_uuid";
    std::shared_ptr<ServiceInfoKvAdapter> serviceInfoKvAdapter = nullptr;
    std::shared_ptr<KvStoreDeathRecipient> deathRecipient = nullptr;
}

class ServiceInfoKvAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class TestKvStoreDeathRecipient : public KvStoreDeathRecipient {
public:
    void OnRemoteDied() override {}
    virtual ~TestKvStoreDeathRecipient() {}
};

void ServiceInfoKvAdapterTest::SetUpTestCase(void)
{
    std::string storeId = "dp_kv_store_service_info_profile";
    deathRecipient = std::make_shared<TestKvStoreDeathRecipient>();
    serviceInfoKvAdapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
}

void ServiceInfoKvAdapterTest::TearDownTestCase(void)
{
    if (serviceInfoKvAdapter != nullptr) {
        serviceInfoKvAdapter->UnInit();
        serviceInfoKvAdapter = nullptr;
    }
    deathRecipient = nullptr;
}

void ServiceInfoKvAdapterTest::SetUp()
{
    if (serviceInfoKvAdapter != nullptr && !serviceInfoKvAdapter->isInited_.load()) {
        serviceInfoKvAdapter->Init();
    }
}

void ServiceInfoKvAdapterTest::TearDown()
{
}

/**
 * @tc.name: Init001
 * @tc.desc: Test Init when already initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Init001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Init());
}

/**
 * @tc.name: UnInit001
 * @tc.desc: Test UnInit when already uninitialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, UnInit001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->UnInit());
}

/**
 * @tc.name: ReInit001
 * @tc.desc: Test ReInit after UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, ReInit001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->ReInit());
}

/**
 * @tc.name: Put001
 * @tc.desc: Test Put with valid key and value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(TEST_KEY, TEST_VALUE));
}

/**
 * @tc.name: Put002
 * @tc.desc: Test Put with empty key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string key = "";
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(key, TEST_VALUE));
}

/**
 * @tc.name: Put003
 * @tc.desc: Test Put with empty value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string value = "";
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(TEST_KEY, value));
}

/**
 * @tc.name: Put004
 * @tc.desc: Test Put with key exceeding MAX_STRING_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put004, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string longKey(MAX_STRING_LEN + 1, 'a');
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(longKey, TEST_VALUE));
}

/**
 * @tc.name: Put005
 * @tc.desc: Test Put with value exceeding MAX_STRING_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put005, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string longValue(MAX_STRING_LEN + 1, 'a');
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(TEST_KEY, longValue));
}

/**
 * @tc.name: Put006
 * @tc.desc: Test Put when kvStorePtr_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Put006, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Put(TEST_KEY, TEST_VALUE));
    serviceInfoKvAdapter->Init();
}

/**
 * @tc.name: Get001
 * @tc.desc: Test Get with existing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Get001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->Put(TEST_KEY, TEST_VALUE);
    std::string value;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Get(TEST_KEY, value));
}

/**
 * @tc.name: Get002
 * @tc.desc: Test Get with non-existing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Get002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string value;
    std::string key = "non_existing_key";
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Get(key, value));
}

/**
 * @tc.name: Get003
 * @tc.desc: Test Get when kvStorePtr_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Get003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    std::string value;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Get(TEST_KEY, value));
    serviceInfoKvAdapter->Init();
}

/**
 * @tc.name: Delete001
 * @tc.desc: Test Delete with existing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Delete001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->Put(TEST_KEY, TEST_VALUE);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Delete(TEST_KEY));
}

/**
 * @tc.name: Delete002
 * @tc.desc: Test Delete with non-existing key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Delete002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string key = "non_existing_key";
    EXPECT_TRUE(DP_READ_PARCEL_FAIL || DP_SUCCESS == serviceInfoKvAdapter->Delete(key));
}

/**
 * @tc.name: Delete003
 * @tc.desc: Test Delete when kvStorePtr_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Delete003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Delete(TEST_KEY));
    serviceInfoKvAdapter->Init();
}

/**
 * @tc.name: DeleteBatch001
 * @tc.desc: Test DeleteBatch with valid keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, DeleteBatch001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::vector<std::string> keys = {"key1", "key2", "key3"};
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->DeleteBatch(keys));
}

/**
 * @tc.name: DeleteBatch002
 * @tc.desc: Test DeleteBatch with empty keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, DeleteBatch002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::vector<std::string> keys;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->DeleteBatch(keys));
}

/**
 * @tc.name: DeleteBatch003
 * @tc.desc: Test DeleteBatch with keys exceeding MAX_PROFILE_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, DeleteBatch003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::vector<std::string> keys(MAX_PROFILE_SIZE + 1, "key");
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->DeleteBatch(keys));
}

/**
 * @tc.name: DeleteBatch004
 * @tc.desc: Test DeleteBatch when kvStorePtr_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, DeleteBatch004, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    std::vector<std::string> keys = {"key1", "key2"};
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->DeleteBatch(keys));
    serviceInfoKvAdapter->Init();
}

/**
 * @tc.name: PutBatch001
 * @tc.desc: Test PutBatch with valid values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, PutBatch001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values = {
        {"key1", "value1"},
        {"key2", "value2"},
        {"key3", "value3"}};
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->PutBatch(values));
}

/**
 * @tc.name: PutBatch002
 * @tc.desc: Test PutBatch with empty values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, PutBatch002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->PutBatch(values));
}

/**
 * @tc.name: PutBatch003
 * @tc.desc: Test PutBatch with values exceeding MAX_PROFILE_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, PutBatch003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values;
    for (int i = 0; i < MAX_PROFILE_SIZE + 1; i++) {
        values["key" + std::to_string(i)] = "value";
    }
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->PutBatch(values));
}

/**
 * @tc.name: PutBatch004
 * @tc.desc: Test PutBatch when kvStorePtr_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, PutBatch004, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    std::map<std::string, std::string> values = {
        {"key1", "value1"},
        {"key2", "value2"}
    };
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->PutBatch(values));
    serviceInfoKvAdapter->Init();
}

/**
 * @tc.name: GetByPrefix001
 * @tc.desc: Test GetByPrefix with existing prefix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, GetByPrefix001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->GetByPrefix(TEST_KEY_PREFIX, values));
}
 
/**
 * @tc.name: DeleteByPrefix001
 * @tc.desc: Test DeleteByPrefix with existing prefix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, DeleteByPrefix001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->DeleteByPrefix(TEST_KEY_PREFIX));
}

/**
 * @tc.name: Sync001
 * @tc.desc: Test Sync with valid device list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, Sync001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::vector<std::string> deviceList = {TEST_DEVICE_ID};
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->Sync(deviceList, SyncMode::PUSH));
}

/**
 * @tc.name: GetDeviceEntries001
 * @tc.desc: Test GetDeviceEntries with valid udid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, GetDeviceEntries001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->GetDeviceEntries(TEST_UUID, values));
}

/**
 * @tc.name: RemoveDeviceData001
 * @tc.desc: Test RemoveDeviceData with valid uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, RemoveDeviceData001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->RemoveDeviceData(TEST_UUID));
}

/**
 * @tc.name: OnRemoteDied001
 * @tc.desc: Test OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceInfoKvAdapterTest, OnRemoteDied001, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->OnRemoteDied();

    EXPECT_TRUE(serviceInfoKvAdapter->isInited_.load());
}
 
/**
 * @tc.name: GetByPrefix002
 * @tc.desc: Test GetByPrefix when kvStorePtr_ is null, expect DP_KV_DB_PTR_NULL
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoKvAdapterTest, GetByPrefix002, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    serviceInfoKvAdapter->UnInit();
    std::map<std::string, std::string> values;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->GetByPrefix("any_prefix", values));
    serviceInfoKvAdapter->Init();
}
 
/**
 * @tc.name: GetByPrefix003
 * @tc.desc: Test GetByPrefix with non-existing prefix, expect DP_INVALID_PARAMS
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoKvAdapterTest, GetByPrefix003, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::map<std::string, std::string> values;
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->GetByPrefix("non_exist_prefix", values));
}
 
/**
 * @tc.name: GetByPrefix004
 * @tc.desc: Test GetByPrefix with too many entries, expect DP_INVALID_PARAMS
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoKvAdapterTest, GetByPrefix004, TestSize.Level1)
{
    ASSERT_NE(nullptr, serviceInfoKvAdapter);
    std::string prefix = "max_prefix_";
    std::map<std::string, std::string> values;
 
    for (size_t i = 0; i < MAX_DB_SIZE + 1; ++i) {
        serviceInfoKvAdapter->Put(prefix + std::to_string(i), "v");
    }
    EXPECT_NE(DP_READ_PARCEL_FAIL, serviceInfoKvAdapter->GetByPrefix(prefix, values));
}
} // namespace DistributedDeviceProfile
} // namespace OHOS