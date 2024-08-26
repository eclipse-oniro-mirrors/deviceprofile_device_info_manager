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

#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_errors.h"
#include "static_capability_collector.h"
#include "static_capability_loader.h"
#include "static_profile_manager.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "StaticCapabilityCollectorTest";
}
class StaticCapabilityCollectorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StaticCapabilityCollectorTest::SetUpTestCase()
{
}

void StaticCapabilityCollectorTest::TearDownTestCase()
{
}

void StaticCapabilityCollectorTest::SetUp()
{
}

void StaticCapabilityCollectorTest::TearDown()
{
}

/*
 * @tc.name: Init_001
 * @tc.desc: Normal testCase of StaticCapabilityCollectorTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityCollectorTest, Init_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityCollector::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

#ifdef DEVICE_PROFILE_SWITCH_STATIC_ENABLE
/*
 * @tc.name: CollectStaticCapability_001
 * @tc.desc: Normal testCase of StaticCapabilityCollectorTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityCollectorTest, CollectStaticCapability_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityCollector::GetInstance().CollectStaticCapability();
    EXPECT_EQ(ret, DP_SUCCESS);
}
#endif // DEVICE_PROFILE_SWITCH_STATIC_ENABLE

/*
 * @tc.name: UnInit_001
 * @tc.desc: Normal testCase of StaticCapabilityCollectorTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityCollectorTest, UnInit_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityCollector::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
