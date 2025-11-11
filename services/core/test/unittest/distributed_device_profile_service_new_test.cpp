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
#include "distributed_device_profile_service_new.h"
#include "kv_adapter.h"
#include "multi_user_manager.h"
#include "profile_utils.h"
#include "permission_manager.h"
#include "service_info_manager.h"
#include "service_info_profile_new.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;

class PermissionManagerTest : public PermissionManager {
public:
    bool CheckCallerPermission()
    {
        return mockCheckPermissionResult;
    }

    static PermissionManagerTest &GetInstance()
    {
        static PermissionManagerTest instance;
        return instance;
    }

    void SetMockCheckPermissionResult(bool result)
    {
        mockCheckPermissionResult = result;
    }

    bool mockCheckPermissionResult = true;
};

class ServiceInfoProfileManageTest : public ServiceInfoProfileManage {
public:
    int32_t PutServiceInfoProfile(const ServiceInfoProfileNew &profile)
    {
        return mockPutServiceInfoResult;
    }

    int32_t GetServiceInfoProfile(ServiceInfoProfileNew &profile)
    {
        return mockGetServiceInfoResult;
    }

    int32_t DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId)
    {
        return mockDeleteServiceInfoResult;
    }

    static ServiceInfoProfileManageTest *GetInstance()
    {
        static ServiceInfoProfileManageTest instance;
        return &instance;
    }

    void SetMockPutServiceInfoResult(int32_t result)
    {
        mockPutServiceInfoResult = result;
    }

    void SetMockGetServiceInfoResult(int32_t result)
    {
        mockGetServiceInfoResult = result;
    }

    void SetMockDeleteServiceInfoResult(int32_t result)
    {
        mockDeleteServiceInfoResult = result;
    }

private:
    int32_t mockPutServiceInfoResult = DP_SUCCESS;
    int32_t mockGetServiceInfoResult = DP_SUCCESS;
    int32_t mockDeleteServiceInfoResult = DP_SUCCESS;
};

class DistributedDeviceProfileServiceNewTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp()
    {
        service = std::make_shared<DistributedDeviceProfileServiceNew>();
        serviceInfoProfile = std::make_shared<ServiceInfoProfileNew>();
    }

    void TearDown()
    {
        service.reset();
        serviceInfoProfile.reset();
    }

    std::shared_ptr<DistributedDeviceProfileServiceNew> service;
    std::shared_ptr<ServiceInfoProfileNew> serviceInfoProfile;
};
HWTEST_F(DistributedDeviceProfileServiceNewTest, PutServiceInfoProfile_001, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(false);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceInfoProfile(serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, PutServiceInfoProfile_002, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockPutServiceInfoResult(DP_SUCCESS);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceInfoProfile(serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, PutServiceInfoProfile_003, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockPutServiceInfoResult(DP_PERMISSION_DENIED);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceInfoProfile(serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, DeleteServiceInfoProfile_001, TestSize.Level1)
{
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(false);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceInfoProfile(
        123, 0);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, DeleteServiceInfoProfile_002, TestSize.Level1)
{
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockDeleteServiceInfoResult(DP_SUCCESS);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceInfoProfile(
        123, 0);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, DeleteServiceInfoProfile_003, TestSize.Level1)
{
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockDeleteServiceInfoResult(DP_PERMISSION_DENIED);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceInfoProfile(
        123, 0);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByServiceId_001, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(false);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByServiceId(
        123, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByServiceId_002, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_SUCCESS);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByServiceId(
        123, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByServiceId_003, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_PERMISSION_DENIED);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByServiceId(
        123, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByTokenId_001, TestSize.Level1)
{
    std::vector<ServiceInfoProfileNew> profiles;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(false);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByTokenId(
        456, profiles);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByTokenId_002, TestSize.Level1)
{
    std::vector<ServiceInfoProfileNew> profiles;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_SUCCESS);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByTokenId(
        456, profiles);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByTokenId_003, TestSize.Level1)
{
    std::vector<ServiceInfoProfileNew> profiles;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_PERMISSION_DENIED);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByTokenId(
        456, profiles);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByRegServiceId_001, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(false);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByRegServiceId(
        321, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByRegServiceId_002, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_SUCCESS);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByRegServiceId(
        321, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileServiceNewTest, GetServiceInfoProfileByRegServiceId_003, TestSize.Level1)
{
    ServiceInfoProfileNew serviceInfoProfile;
    PermissionManagerTest::GetInstance().SetMockCheckPermissionResult(true);
    ServiceInfoProfileManageTest::GetInstance()->SetMockGetServiceInfoResult(DP_PERMISSION_DENIED);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetServiceInfoProfileByRegServiceId(
        321, serviceInfoProfile);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
