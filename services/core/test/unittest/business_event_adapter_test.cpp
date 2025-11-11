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
#include "business_event_adapter.h"
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
    const std::string STORE_ID = "dp_kv_store_business";
    shared_ptr<IKVAdapter> kvStore = nullptr;
}

class BusinessAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BusinessAdapterTest::SetUpTestCase(void)
{
    kvStore = make_shared<BusinessEventAdapter>(make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
}

void BusinessAdapterTest::TearDownTestCase(void) {
}

void BusinessAdapterTest::SetUp()
{
    kvStore->Init();
}

void BusinessAdapterTest::TearDown()
{
    kvStore->UnInit();
}

/**
 * @tc.name: Init001
 * @tc.desc: Init succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Init001, TestSize.Level1)
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
HWTEST_F(BusinessAdapterTest, UnInit001, TestSize.Level1)
{
    EXPECT_EQ(DP_SUCCESS, kvStore->UnInit());
}

/**
 * @tc.name: Put001
 * @tc.desc: Put succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Put001, TestSize.Level1)
{
    EXPECT_EQ(DP_SUCCESS, kvStore->Put("business_id_cast+_disturbance_event", "value"));
}

/**
 * @tc.name: Put002
 * @tc.desc: Put failed, Param is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Put002, TestSize.Level1)
{
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put("", "value"));
    EXPECT_EQ(DP_INVALID_PARAMS, kvStore->Put("key", ""));
}

/**
 * @tc.name: Put003
 * @tc.desc: Put failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Put003, TestSize.Level1)
{
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Put("key", "value"));
}

/**
 * @tc.name: Put004
 * @tc.desc: Put first if.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Put004, TestSize.Level1)
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
 * @tc.name: Delete001
 * @tc.desc: Delete succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Delete001, TestSize.Level1)
{
    kvStore->Put("key", "value");
    EXPECT_EQ(DP_SUCCESS, kvStore->Delete("key"));
}

/**
 * @tc.name: Delete002
 * @tc.desc: Delete failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Delete002, TestSize.Level1)
{
    kvStore->Put("key", "value");
    kvStore->UnInit();
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Delete("key"));
}

/**
 * @tc.name: Get001
 * @tc.desc: Get succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Get001, TestSize.Level1)
{
    kvStore->Put("business_id_cast+_disturbance_event", "value");
    string value;
    EXPECT_EQ(DP_SUCCESS, kvStore->Get("business_id_cast+_disturbance_event", value));
    EXPECT_EQ("value", value);
}

/**
 * @tc.name: Get002
 * @tc.desc: Get failed, kvDBPtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusinessAdapterTest, Get002, TestSize.Level1)
{
    kvStore->Put("business_id_cast+_disturbance_event", "value");
    kvStore->UnInit();
    string value;
    EXPECT_EQ(DP_KV_DB_PTR_NULL, kvStore->Get("business_id_cast+_disturbance_event", value));
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
