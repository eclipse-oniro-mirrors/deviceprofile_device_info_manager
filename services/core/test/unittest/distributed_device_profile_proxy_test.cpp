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
#include "service_info.h"
#include "user_info.h"
#include "distributed_device_profile_proxy.h"
#include "distributed_device_profile_errors.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
using namespace std;

class DistributedDeviceProfileProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: PutServiceInfo_001
 * @tc.desc: PutServiceInfo with nullptr remote object
 *           Step 1: Create proxy with nullptr remote object
 *           Step 2: Call PutServiceInfo with valid ServiceInfo
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, PutServiceInfo_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    ServiceInfo serviceInfo;
    serviceInfo.SetServiceName("test_service");
    serviceInfo.SetUdid("test_udid");

    int32_t ret = proxy.PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: PutServiceInfo_002
 * @tc.desc: PutServiceInfo with empty ServiceInfo and nullptr remote
 *           Step 1: Create proxy with nullptr and empty ServiceInfo
 *           Step 2: Call PutServiceInfo with empty info
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, PutServiceInfo_002, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    ServiceInfo serviceInfo;

    int32_t ret = proxy.PutServiceInfo(serviceInfo);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: DeleteServiceInfo_001
 * @tc.desc: DeleteServiceInfo with nullptr remote object
 *           Step 1: Create proxy with nullptr remote object
 *           Step 2: Call DeleteServiceInfo with valid UserInfo
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, DeleteServiceInfo_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    UserInfo userInfo;
    userInfo.udid = "test_udid";
    userInfo.userId = 100;
    userInfo.serviceId = 1001;

    int32_t ret = proxy.DeleteServiceInfo(userInfo);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: DeleteServiceInfo_002
 * @tc.desc: DeleteServiceInfo with empty UserInfo and nullptr remote
 *           Step 1: Create proxy with nullptr and empty UserInfo
 *           Step 2: Call DeleteServiceInfo with empty info
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, DeleteServiceInfo_002, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    UserInfo userInfo;

    int32_t ret = proxy.DeleteServiceInfo(userInfo);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: GetAllServiceInfoList_001
 * @tc.desc: GetAllServiceInfoList with nullptr remote object
 *           Step 1: Create proxy with nullptr remote object
 *           Step 2: Call GetAllServiceInfoList with empty vector
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, GetAllServiceInfoList_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = proxy.GetAllServiceInfoList(serviceInfos);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: GetAllServiceInfoList_002
 * @tc.desc: GetAllServiceInfoList with pre-allocated vector and nullptr remote
 *           Step 1: Create proxy with nullptr and pre-allocated vector
 *           Step 2: Call GetAllServiceInfoList
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, GetAllServiceInfoList_002, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    std::vector<ServiceInfo> serviceInfos;
    serviceInfos.reserve(10);

    int32_t ret = proxy.GetAllServiceInfoList(serviceInfos);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: GetServiceInfosByUserInfo_001
 * @tc.desc: GetServiceInfosByUserInfo with nullptr remote object
 *           Step 1: Create proxy with nullptr remote object
 *           Step 2: Call GetServiceInfosByUserInfo with valid UserInfo
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, GetServiceInfosByUserInfo_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    UserInfo userInfo;
    userInfo.udid = "test_udid";
    userInfo.userId = 100;
    userInfo.serviceId = 1001;
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = proxy.GetServiceInfosByUserInfo(userInfo, serviceInfos);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: GetServiceInfosByUserInfo_002
 * @tc.desc: GetServiceInfosByUserInfo with empty UserInfo and nullptr remote
 *           Step 1: Create proxy with nullptr and empty UserInfo
 *           Step 2: Call GetServiceInfosByUserInfo with empty info
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, GetServiceInfosByUserInfo_002, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    UserInfo userInfo;
    std::vector<ServiceInfo> serviceInfos;

    int32_t ret = proxy.GetServiceInfosByUserInfo(userInfo, serviceInfos);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: SubscribeAllServiceInfo_001
 * @tc.desc: SubscribeAllServiceInfo with nullptr remote object
 *           Step 1: Create proxy with nullptr remote object
 *           Step 2: Call SubscribeAllServiceInfo with valid saId and listener
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, SubscribeAllServiceInfo_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    int32_t saId = 4801;
    sptr<IRemoteObject> listener = nullptr;

    int32_t ret = proxy.SubscribeAllServiceInfo(saId, listener);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: SubscribeAllServiceInfo_002
 * @tc.desc: SubscribeAllServiceInfo with nullptr listener and nullptr remote
 *           Step 1: Create proxy with nullptr and nullptr listener
 *           Step 2: Call SubscribeAllServiceInfo
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, SubscribeAllServiceInfo_002, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    int32_t saId = 4801;
    sptr<IRemoteObject> listener = nullptr;

    int32_t ret = proxy.SubscribeAllServiceInfo(saId, listener);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

/**
 * @tc.name: SubscribeAllServiceInfo_003
 * @tc.desc: SubscribeAllServiceInfo with zero saId and nullptr remote
 *           Step 1: Create proxy with nullptr and zero saId
 *           Step 2: Call SubscribeAllServiceInfo with zero saId
 *           Step 3: Verify return value indicates remote object is null
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileProxyTest, SubscribeAllServiceInfo_003, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);

    int32_t saId = 0;
    sptr<IRemoteObject> listener = nullptr;

    int32_t ret = proxy.SubscribeAllServiceInfo(saId, listener);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

}  //namespace DistributedDeviceProfile
}  //namespace OHOS
