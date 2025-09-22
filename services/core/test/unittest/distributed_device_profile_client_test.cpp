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
#include "distributed_device_profile_client.h"
#include "service_info_profile_new.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;


class DistributedDeviceProfileClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(DistributedDeviceProfileClientTest, PutServiceInfoProfile_001, TestSize.Level1)
{
    DistributedDeviceProfileClient client;
    ServiceInfoProfileNew profile;
    
    int32_t ret = client.PutServiceInfoProfile(profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileClientTest, DelServiceInfoProfile_001, TestSize.Level1)
{
    DistributedDeviceProfileClient client;
    int32_t regServiceId = 123;
    int32_t userId = 0;
    int32_t ret = client.DeleteServiceInfoProfile(regServiceId, userId);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileClientTest, GetServiceInfoProfileByServiceId_001, TestSize.Level1)
{
    DistributedDeviceProfileClient client;
    ServiceInfoProfileNew profile;
    int64_t serviceId = 0;
    int32_t ret = client.GetServiceInfoProfileByServiceId(serviceId, profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}

HWTEST_F(DistributedDeviceProfileClientTest, GetServiceInfoProfileByTokenId_001, TestSize.Level1)
{
    DistributedDeviceProfileClient client;
    ServiceInfoProfileNew profile;
    int64_t tokenId = 0;
    int32_t ret = client.GetServiceInfoProfileByTokenId(tokenId, profile);
    EXPECT_FALSE(ret == DP_READ_PARCEL_FAIL);
}
}  //namespace DistributedDeviceProfile
}  //namespace OHOS