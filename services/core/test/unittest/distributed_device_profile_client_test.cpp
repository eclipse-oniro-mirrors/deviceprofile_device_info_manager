/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include "distributed_device_profile_client.h"
#include "service_info.h"
#include "distributed_device_profile_errors.h"
#include "mock/distributed_device_profile_mock.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
using namespace std;


class DistributedDeviceProfileClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override
    {
        DistributedDeviceProfileClient::GetInstance().dpProxy_ = nullptr;
    }

private:
    class TestRemoteObject : public IRemoteObject {
    public:
        TestRemoteObject() = default;
        ~TestRemoteObject() override = default;

        int32_t SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
            MessageOption& option) override
        {
            return 0;
        }

        sptr<IRemoteObject> AsObject()
        {
            return this;
        }

        int32_t GetObjectRefCount() override
        {
            return 0;
        }

        bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override
        {
            return false;
        }

        bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient) override
        {
            return false;
        }

        int32_t Dump(int fd, const std::vector<std::u16string>& args) override
        {
            return 0;
        }
    };
};

/**
 * @tc.name: PutServiceInfo_001
 * @tc.desc: PutServiceInfo when service is not available
 *           Step 1: Prepare ServiceInfo without service setup
 *           Step 2: Call PutServiceInfo
 *           Step 3: Verify return value indicates service failure
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, PutServiceInfo_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUdid("test_udid_001");
    serviceInfo.SetUserId(100);
    serviceInfo.SetServiceName("test_service");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_GET_SERVICE_FAILED);
}

/**
 * @tc.name: PutServiceInfo_002
 * @tc.desc: PutServiceInfo with mocked service returning DP_SUCCESS
 *           Step 1: Create mock service returning DP_SUCCESS and inject
 *           Step 2: Call PutServiceInfo with valid data
 *           Step 3: Verify return value is DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, PutServiceInfo_002, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, PutServiceInfo(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    ServiceInfo serviceInfo;
    serviceInfo.SetServiceName("test_service");
    serviceInfo.SetUdid("test_udid");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: PutServiceInfo_003
 * @tc.desc: PutServiceInfo with mocked service returning DP_WRITE_PARCEL_FAIL
 *           Step 1: Create mock service returning DP_WRITE_PARCEL_FAIL and inject
 *           Step 2: Call PutServiceInfo
 *           Step 3: Verify return value indicates failure
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, PutServiceInfo_003, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, PutServiceInfo(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_WRITE_PARCEL_FAIL));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    ServiceInfo serviceInfo;
    serviceInfo.SetServiceName("test_service");

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_WRITE_PARCEL_FAIL);
}

/**
 * @tc.name: PutServiceInfo_004
 * @tc.desc: PutServiceInfo with empty ServiceInfo and mocked service
 *           Step 1: Create mock service and empty ServiceInfo
 *           Step 2: Call PutServiceInfo with empty info
 *           Step 3: Verify return value from mock
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, PutServiceInfo_004, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, PutServiceInfo(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    ServiceInfo serviceInfo;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteServiceInfo_001
 * @tc.desc: DeleteServiceInfo when service is not available
 *           Step 1: Prepare UserInfo without service setup
 *           Step 2: Call DeleteServiceInfo
 *           Step 3: Verify return value indicates service failure
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, DeleteServiceInfo_001, TestSize.Level1)
{
    UserInfo userInfo;
    userInfo.udid = "test_udid_001";
    userInfo.userId = 100;
    userInfo.serviceId = 1001;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().DeleteServiceInfo(userInfo);
    EXPECT_EQ(ret, DP_GET_SERVICE_FAILED);
}

/**
 * @tc.name: DeleteServiceInfo_002
 * @tc.desc: DeleteServiceInfo with mocked service returning DP_SUCCESS
 *           Step 1: Create mock service returning DP_SUCCESS and inject
 *           Step 2: Call DeleteServiceInfo with valid UserInfo
 *           Step 3: Verify return value is DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, DeleteServiceInfo_002, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, DeleteServiceInfo(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    UserInfo userInfo;
    userInfo.udid = "test_udid";
    userInfo.userId = 100;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().DeleteServiceInfo(userInfo);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteServiceInfo_003
 * @tc.desc: DeleteServiceInfo with empty UserInfo and mocked service
 *           Step 1: Create mock service and empty UserInfo
 *           Step 2: Call DeleteServiceInfo with empty info
 *           Step 3: Verify return value from mock
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, DeleteServiceInfo_003, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, DeleteServiceInfo(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    UserInfo userInfo;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().DeleteServiceInfo(userInfo);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetAllServiceInfoList_001
 * @tc.desc: GetAllServiceInfoList when service is not available
 *           Step 1: Prepare vector without service setup
 *           Step 2: Call GetAllServiceInfoList
 *           Step 3: Verify return value indicates service failure
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetAllServiceInfoList_001, TestSize.Level1)
{
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAllServiceInfoList(serviceInfos);
    EXPECT_EQ(ret, DP_GET_SERVICE_FAILED);
}

/**
 * @tc.name: GetAllServiceInfoList_002
 * @tc.desc: GetAllServiceInfoList with mocked service returning DP_SUCCESS
 *           Step 1: Create mock service returning DP_SUCCESS and inject
 *           Step 2: Call GetAllServiceInfoList
 *           Step 3: Verify return value is DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetAllServiceInfoList_002, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, GetAllServiceInfoList(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAllServiceInfoList(serviceInfos);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetAllServiceInfoList_003
 * @tc.desc: GetAllServiceInfoList with pre-allocated vector and mocked service
 *           Step 1: Create mock service and vector with reserved capacity
 *           Step 2: Call GetAllServiceInfoList
 *           Step 3: Verify return value is DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetAllServiceInfoList_003, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, GetAllServiceInfoList(testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    std::vector<ServiceInfo> serviceInfos;
    serviceInfos.reserve(10);

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAllServiceInfoList(serviceInfos);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetServiceInfosByUserInfo_001
 * @tc.desc: GetServiceInfosByUserInfo when service is not available
 *           Step 1: Prepare UserInfo and vector without service setup
 *           Step 2: Call GetServiceInfosByUserInfo
 *           Step 3: Verify return value indicates service failure
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetServiceInfosByUserInfo_001, TestSize.Level1)
{
    UserInfo userInfo;
    userInfo.udid = "test_udid_001";
    userInfo.userId = 100;
    userInfo.serviceId = 1001;
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetServiceInfosByUserInfo(userInfo, serviceInfos);
    EXPECT_EQ(ret, DP_GET_SERVICE_FAILED);
}

/**
 * @tc.name: GetServiceInfosByUserInfo_002
 * @tc.desc: GetServiceInfosByUserInfo with mocked service returning DP_SUCCESS
 *           Step 1: Create mock service returning DP_SUCCESS and inject
 *           Step 2: Call GetServiceInfosByUserInfo with valid UserInfo
 *           Step 3: Verify return value is DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetServiceInfosByUserInfo_002, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, GetServiceInfosByUserInfo(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    UserInfo userInfo;
    userInfo.udid = "test_udid";
    userInfo.userId = 100;
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetServiceInfosByUserInfo(userInfo, serviceInfos);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetServiceInfosByUserInfo_003
 * @tc.desc: GetServiceInfosByUserInfo with empty UserInfo and mocked service
 *           Step 1: Create mock service and empty UserInfo
 *           Step 2: Call GetServiceInfosByUserInfo with empty info
 *           Step 3: Verify return value from mock
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, GetServiceInfosByUserInfo_003, TestSize.Level1)
{
    auto mockService = sptr<IDistributedDeviceProfileMock>(new IDistributedDeviceProfileMock());

    EXPECT_CALL(*mockService, GetServiceInfosByUserInfo(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(DP_SUCCESS));

    DistributedDeviceProfileClient::GetInstance().dpProxy_ = mockService;

    UserInfo userInfo;
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetServiceInfosByUserInfo(userInfo, serviceInfos);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: ReSubscribeAllServiceInfo_001
 * @tc.desc: ReSubscribeAllServiceInfo without prior subscription
 *           Step 1: Call ReSubscribeAllServiceInfo without setup
 *           Step 2: Verify no crash occurs
 *           Step 3: Method should return early safely
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientTest, ReSubscribeAllServiceInfo_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        DistributedDeviceProfileClient::GetInstance().ReSubscribeAllServiceInfo()
    );
}

}  //namespace DistributedDeviceProfile
}  //namespace OHOS
