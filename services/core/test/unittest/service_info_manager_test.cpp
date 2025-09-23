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
#include "service_info_profile_new.h"
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

HWTEST_F(ServiceInfoProfileManageTest, PutServiceInfoProfile_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    ServiceInfoProfileNew profile;
    profile.SetUserId(100);
 
    int32_t ret = manager.PutServiceInfoProfile(profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, PutServiceInfoProfile_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    ServiceInfoProfileNew invalidProfile;
    int32_t ret = manager.PutServiceInfoProfile(invalidProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, PutServiceInfoProfile_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;
    
    ServiceInfoProfileNew profile;
    profile.SetUserId(100);
 
    int32_t ret = manager.PutServiceInfoProfile(profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, PutServiceInfoProfile_004, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);
    ServiceInfoProfileNew profile;
    profile.SetUserId(100);
 
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            int32_t ret = manager.PutServiceInfoProfile(profile);
            if (ret == DP_SUCCESS) successCount++;
        });
    }
 
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(successCount.load(), 0);
}

HWTEST_F(ServiceInfoProfileManageTest, DeleteServiceInfoProfile_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    int32_t regServiceId = 123;
    int32_t userId = 100;
 
    int32_t ret = manager.DeleteServiceInfoProfile(regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, DeleteServiceInfoProfile_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;
    
    int32_t regServiceId = 123;
    int32_t userId = 100;
 
    int32_t ret = manager.DeleteServiceInfoProfile(regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, DeleteServiceInfoProfile_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    int32_t regServiceId = 123;
    int32_t userId = 100;
 
    int32_t ret = manager.DeleteServiceInfoProfile(regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, DeleteServiceInfoProfile_004, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);
    int32_t regServiceId = 123;
    int32_t userId = 100;
 
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            int32_t ret = manager.DeleteServiceInfoProfile(regServiceId, userId);
            if (ret == DP_SUCCESS) successCount++;
        });
    }
 
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_NE(successCount.load(), -1);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByServiceId_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::map<std::string, std::string> testData = {
        {"serviceInfo#123#serviceId", "456"},
        {"serviceInfo#123#name", "TestService"}
    };
    manager.serviceInfoKvAdapter_->PutBatch(testData);
 
    int64_t serviceId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByServiceId_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;
    
    int64_t serviceId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByServiceId_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::map<std::string, std::string> testData = {
        {"serviceInfo#123#serviceId", "789"},
        {"serviceInfo#123#name", "TestService"}
    };
    manager.serviceInfoKvAdapter_->PutBatch(testData);
 
    int64_t serviceId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByServiceId_004, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<MockFailKvAdapter>();
    
    int64_t serviceId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByServiceId_005, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::map<std::string, std::string> testData = {
        {"serviceInfo#123#serviceId", "456"},
        {"serviceInfo#123#name", "TestService"}
    };
    manager.serviceInfoKvAdapter_->PutBatch(testData);
 
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);
    int64_t serviceId = 456;
 
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            ServiceInfoProfileNew profile;
            int32_t ret = manager.GetServiceInfoProfileByServiceId(serviceId, profile);
            if (ret == DP_SUCCESS) successCount++;
        });
    }
 
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_NE(successCount.load(), -1);
}

HWTEST_F(ServiceInfoProfileManageTest, SetServiceInfoProfile_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    std::string regServiceId = "123";
    std::map<std::string, std::string> finalSerProfile = {
        {"serviceInfo#123#deviceId", "device001"},
        {"serviceInfo#123#publishState", "1"},
        {"serviceInfo#123#serviceDisplayName", "TestService"},
        {"serviceInfo#123#serviceId", "456"},
        {"serviceInfo#123#serviceName", "TestServiceName"},
        {"serviceInfo#123#serviceType", "TypeA"},
        {"serviceInfo#123#tokenId", "789"},
        {"serviceInfo#123#userId", "100"}
    };
    ServiceInfoProfileNew profile;

    manager.SetServiceInfoProfile(regServiceId, finalSerProfile, profile);

    EXPECT_EQ(profile.GetRegServiceId(), 123);
    EXPECT_EQ(profile.GetDeviceId(), "device001");
    EXPECT_EQ(profile.GetSerPubState(), 1);
    EXPECT_EQ(profile.GetServiceDisplayName(), "TestService");
    EXPECT_EQ(profile.GetServiceId(), 456);
    EXPECT_EQ(profile.GetServiceName(), "TestServiceName");
    EXPECT_EQ(profile.GetServiceType(), "TypeA");
    EXPECT_EQ(profile.GetTokenId(), 789);
    EXPECT_EQ(profile.GetUserId(), 100);
}

HWTEST_F(ServiceInfoProfileManageTest, SetServiceInfoProfile_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    std::string regServiceId = "123";
    std::map<std::string, std::string> finalSerProfile = {
        {"serviceInfo#123#deviceId", "device001"},
        {"serviceInfo#123#serviceId", "456"}
    };
    ServiceInfoProfileNew profile;

    manager.SetServiceInfoProfile(regServiceId, finalSerProfile, profile);

    EXPECT_EQ(profile.GetSerPubState(), 0);
    EXPECT_TRUE(profile.GetServiceDisplayName().empty());
    EXPECT_TRUE(profile.GetServiceName().empty());
    EXPECT_TRUE(profile.GetServiceType().empty());
    EXPECT_EQ(profile.GetTokenId(), 0);
    EXPECT_NE(profile.GetUserId(), -2);
}

HWTEST_F(ServiceInfoProfileManageTest, SetServiceInfoProfile_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    std::string regServiceId = "123";
    std::map<std::string, std::string> finalSerProfile;
    ServiceInfoProfileNew profile;

    manager.SetServiceInfoProfile(regServiceId, finalSerProfile, profile);

    EXPECT_TRUE(profile.GetDeviceId().empty());
    EXPECT_EQ(profile.GetSerPubState(), 0);
    EXPECT_TRUE(profile.GetServiceDisplayName().empty());
    EXPECT_EQ(profile.GetServiceId(), 0);
    EXPECT_TRUE(profile.GetServiceName().empty());
    EXPECT_TRUE(profile.GetServiceType().empty());
    EXPECT_EQ(profile.GetTokenId(), 0);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByTokenId_001, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    
    std::map<std::string, std::string> testData = {
        {"serviceInfo#123#tokenId", "456"},
        {"serviceInfo#123#name", "TestService"}
    };
    manager.serviceInfoKvAdapter_->PutBatch(testData);

    int64_t tokenId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByTokenId(tokenId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByTokenId_002, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = nullptr;

    int64_t tokenId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByTokenId(tokenId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByTokenId_003, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<ServiceInfoKvAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);

    std::map<std::string, std::string> testData = {
        {"serviceInfo#123#tokenId", "789"},
        {"serviceInfo#123#name", "TestService"}
    };
    manager.serviceInfoKvAdapter_->PutBatch(testData);

    int64_t tokenId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByTokenId(tokenId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}
 
HWTEST_F(ServiceInfoProfileManageTest, GetServiceInfoProfileByTokenId_004, testing::ext::TestSize.Level1)
{
    ServiceInfoProfileManage manager;
    manager.serviceInfoKvAdapter_ = std::make_shared<MockFailKvAdapter>();

    int64_t tokenId = 456;
    ServiceInfoProfileNew profile;
    int32_t ret = manager.GetServiceInfoProfileByTokenId(tokenId, profile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS