/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dm_adapter.h"
#include "event_handler_factory.h"
using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "DMAdapterTest";
}
class DMAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DMAdapterTest::SetUpTestCase()
{
}

void DMAdapterTest::TearDownTestCase()
{
}

void DMAdapterTest::SetUp()
{
}

void DMAdapterTest::TearDown()
{
}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMAdapterTest, Init001, TestSize.Level1)
{
    DMAdapter::GetInstance().dmInitCallback_ = nullptr;
    DMAdapter::GetInstance().deviceStateCallback_ = nullptr;
    int32_t ret = DMAdapter::GetInstance().Init();
    EXPECT_NE(DP_INVALID_PARAMS, ret);
    ret = DMAdapter::GetInstance().UnInit();
    EXPECT_EQ(DP_SUCCESS, ret);
}

/*
 * @tc.name: UnInit001
 * @tc.desc: UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMAdapterTest, UnInit001, TestSize.Level1)
{
    DMAdapter::GetInstance().dmInitCallback_ = nullptr;
    DMAdapter::GetInstance().deviceStateCallback_ = nullptr;
    int32_t ret = DMAdapter::GetInstance().UnInit();
    EXPECT_EQ(DP_SUCCESS, ret);
}

/*
 * @tc.name: UnInit002
 * @tc.desc: UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMAdapterTest, UnInit002, TestSize.Level1)
{
    int32_t ret = DMAdapter::GetInstance().Init();
    EXPECT_NE(DP_INVALID_PARAMS, ret);
    ret = DMAdapter::GetInstance().UnInit();
    EXPECT_EQ(DP_SUCCESS, ret);
}

/*
 * @tc.name: ReInit001
 * @tc.desc: ReInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMAdapterTest, ReInit001, TestSize.Level1)
{
    int32_t ret = DMAdapter::GetInstance().ReInit();
    EXPECT_NE(DP_INVALID_PARAMS, ret);
    ret = DMAdapter::GetInstance().UnInit();
    EXPECT_EQ(DP_SUCCESS, ret);
}

/*
 * @tc.name: GetUuidByNetworkId001
 * @tc.desc: GetUuidByNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMAdapterTest, GetUuidByNetworkId001, TestSize.Level1)
{
    std::string networkId = "networkId";
    std::string uuid = "";
    bool ret = DMAdapter::GetInstance().GetUuidByNetworkId(networkId, uuid);
    EXPECT_FALSE(ret);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
