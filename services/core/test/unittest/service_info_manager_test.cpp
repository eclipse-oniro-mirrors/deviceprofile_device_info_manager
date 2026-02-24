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

#include <gtest/gtest.h>
#include <memory>
#include <map>
#include <string>

#include "distributed_device_profile_errors.h"
#include "kv_adapter.h"
#include "kv_store_death_recipient.h"
#include "multi_user_manager.h"
#include "profile_utils.h"
#include "profile_control_utils.h"
#include "service_info_manager.h"
#include "service_info_kv_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ServiceInfoProfileManage)

namespace {
    const std::string DP_REJECT_KEY = "business_id_cast+_reject_event";
    const std::string DP_DISTURBANCE_KEY = "business_id_cast+_disturbance_event";
    const std::string STORE_ID = "dp_kv_store_service_info_profile";
    const std::string TAG = "ServiceInfoProfileManage";
    const std::set<std::string> validKeys_ = {DP_REJECT_KEY, DP_DISTURBANCE_KEY};
}

class MockFailKvAdapter : public ServiceInfoKvAdapter {
public:
    MockFailKvAdapter()
        : ServiceInfoKvAdapter(std::make_shared<KvDeathRecipient>(STORE_ID),
                               DistributedKv::TYPE_DYNAMICAL) {}
    int32_t Init() override { return DP_INIT_DB_FAILED; }
};

class MockFailProfileControlUtils : public ProfileControlUtils {
public:
    static int32_t DeleteServiceInfoProfile(
        std::shared_ptr<ServiceInfoKvAdapter> adapter, int32_t regServiceId, int32_t userId)
    {
        return DP_DEL_KV_DB_FAIL;
    }
};

class ServiceInfoProfileManageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ServiceInfoProfileManageTest::SetUpTestCase(void) {}

void ServiceInfoProfileManageTest::TearDownTestCase(void) {}

void ServiceInfoProfileManageTest::SetUp() {}

void ServiceInfoProfileManageTest::TearDown() {}

HWTEST_F(ServiceInfoProfileManageTest, Init_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    int32_t ret = manager.Init();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
    EXPECT_NE(manager.serviceInfoKvAdapter_, nullptr);
}

HWTEST_F(ServiceInfoProfileManageTest, Init_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            int32_t ret = manager.Init();
            if (ret == DP_SUCCESS) successCount++;
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    EXPECT_NE(successCount.load(), -1);
    EXPECT_NE(manager.serviceInfoKvAdapter_, nullptr);
}

HWTEST_F(ServiceInfoProfileManageTest, Init_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<MockFailKvAdapter>();
    int32_t ret = manager.Init();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, UnInit_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t ret = manager.UnInit();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, UnInit_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;
    int32_t ret = manager.UnInit();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, UnInit_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);

    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            int32_t ret = manager.UnInit();
            if (ret == DP_SUCCESS) successCount++;
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    EXPECT_NE(successCount.load(), -1);
    EXPECT_EQ(manager.serviceInfoKvAdapter_, nullptr);
}

HWTEST_F(ServiceInfoProfileManageTest, ReInit_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t ret = manager.ReInit();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
    EXPECT_NE(manager.serviceInfoKvAdapter_, nullptr);
}

HWTEST_F(ServiceInfoProfileManageTest, ReInit_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;
    int32_t ret = manager.ReInit();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, ReInit_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<MockFailKvAdapter>();
    int32_t ret = manager.ReInit();
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, ReInit_004, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);

    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            int32_t ret = manager.ReInit();
            if (ret == DP_SUCCESS) successCount++;
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    EXPECT_NE(successCount.load(), -1);
    EXPECT_NE(manager.serviceInfoKvAdapter_, nullptr);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS