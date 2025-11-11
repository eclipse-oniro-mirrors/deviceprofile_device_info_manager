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
#include "service_info_profile_new.h"
#include "distributed_device_profile_proxy.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class DistributedDeviceProfileProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(DistributedDeviceProfileProxyTest, PutServiceInfoProfile_001, TestSize.Level0)
{
    DistributedDeviceProfileProxy proxy(nullptr);
    ServiceInfoProfileNew profile;

    int32_t ret = proxy.PutServiceInfoProfile(profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileProxyTest, DeleteServiceInfoProfile_001, TestSize.Level0)
{
    DistributedDeviceProfileProxy proxy(nullptr);
    int32_t regServiceId = 123;
    int32_t userId = 0;
    int32_t ret = proxy.DeleteServiceInfoProfile(regServiceId, userId);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileProxyTest, GetServiceInfoProfileByServiceId_001, TestSize.Level0)
{
    DistributedDeviceProfileProxy proxy(nullptr);
    ServiceInfoProfileNew profile;
    int64_t serviceId = 0;
    int32_t ret = proxy.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileProxyTest, GetServiceInfoProfileByTokenId_001, TestSize.Level0)
{
    DistributedDeviceProfileProxy proxy(nullptr);
    std::vector<ServiceInfoProfileNew> profiles;
    int64_t tokenId = 0;
    int32_t ret = proxy.GetServiceInfoProfileByTokenId(tokenId, profiles);
    EXPECT_EQ(ret, DP_IPC_REMOTE_OBJECT_NULLPTR);
}

HWTEST_F(DistributedDeviceProfileProxyTest, GetServiceInfoProfileByRegServiceId_001, TestSize.Level1)
{
    DistributedDeviceProfileProxy proxy(nullptr);
    ServiceInfoProfileNew profile;
    int32_t regServiceId = 0;
    int32_t ret = proxy.GetServiceInfoProfileByRegServiceId(regServiceId, profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}
}  //namespace DistributedDeviceProfile
}  //namespace OHOS