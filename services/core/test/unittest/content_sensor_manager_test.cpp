/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>
#include <iostream>

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#define private public
#define protected public

#include "content_sensor_manager.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "ContentSensorManagerTest";
}
class ContentSensorManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ContentSensorManagerTest::SetUpTestCase()
{
}

void ContentSensorManagerTest::TearDownTestCase()
{
}

void ContentSensorManagerTest::SetUp()
{
}

void ContentSensorManagerTest::TearDown()
{
}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerTest, Init001, TestSize.Level1)
{
    ContentSensorManager contentSensorManager_;
    int32_t result = contentSensorManager_.Init();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: UnInit001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContentSensorManagerTest, UnInit001, TestSize.Level1)
{
    ContentSensorManager contentSensorManager_;
    int32_t result = contentSensorManager_.UnInit();
    EXPECT_EQ(result, 0);
}
}
}
