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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>

#include "switch_adapter.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "kv_data_change_listener.h"
#include "types.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "SwitchAdapterTest";
}
class SwitchAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SwitchAdapterTest::SetUpTestCase()
{
    OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().Init();
}

void SwitchAdapterTest::TearDownTestCase()
{
    OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().Uninit();
}

void SwitchAdapterTest::SetUp()
{
}

void SwitchAdapterTest::TearDown()
{
}

/*
 * @tc.name: PutSwitch_001
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, PutSwitch_001, TestSize.Level1)
{
    const std::string appId;
    uint32_t value = 1;
    uint16_t length = 1;
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().PutSwitch(appId, value, length);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: PutSwitch_002
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, PutSwitch_002, TestSize.Level1)
{
    const std::string appId = "6666";
    uint32_t value = 1;
    uint16_t length = 1;
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().PutSwitch(appId, value, length);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/*
 * @tc.name: GetSwitch_001
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, GetSwitch_001, TestSize.Level1)
{
    const std::string appId = "";
    std::string networkId = "networkId";
    uint32_t value = 1;
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().GetSwitch(appId, networkId, value);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetSwitch_002
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, GetSwitch_002, TestSize.Level1)
{
    const std::string appId = "appid";
    std::string networkId = "";
    uint32_t value = 1;
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().GetSwitch(appId, networkId, value);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetSwitch_003
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, GetSwitch_003, TestSize.Level1)
{
    const std::string appId = "appid";
    std::string networkId = "networkId";
    uint32_t value = 1;
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().GetSwitch(appId, networkId, value);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/*
 * @tc.name: SubscribeSwitchData_001
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, SubscribeSwitchData_001, TestSize.Level1)
{
    const std::string appId = "";
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().SubscribeSwitchData(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: SubscribeSwitchData_002
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, SubscribeSwitchData_002, TestSize.Level1)
{
    const std::string appId = "appid";
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().SubscribeSwitchData(appId);
    EXPECT_EQ(ret, DP_SUBSCRIBE_FAILED);
}

/*
 * @tc.name: UnsubscribeSwitchData_001
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, UnsubscribeSwitchData_001, TestSize.Level1)
{
    const std::string appId = "";
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().SubscribeSwitchData(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/*
 * @tc.name: UnsubscribeSwitchData_002
 * @tc.desc: Normal testCase of SwitchAdapterTest
 * @tc.type: FUNC
 */
HWTEST_F(SwitchAdapterTest, UnsubscribeSwitchData_002, TestSize.Level1)
{
    const std::string appId = "appid";
    int32_t ret = OHOS::DistributedDeviceProfile::
        SwitchAdapter::GetInstance().SubscribeSwitchData(appId);
    EXPECT_EQ(ret, DP_SUBSCRIBE_FAILED);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS