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
#include <vector>
#include <iostream>

#include "multi_user_manager.h"
#include "distributed_device_profile_errors.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "MultiUserManagerTest";
}
class MultiUserManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MultiUserManagerTest::SetUpTestCase()
{
}

void MultiUserManagerTest::TearDownTestCase()
{
}

void MultiUserManagerTest::SetUp()
{
}

void MultiUserManagerTest::TearDown()
{
}

/*
 * @tc.name: init
 * @tc.desc: Normal testCase of MultiUserManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, init_001, TestSize.Level1)
{
    int32_t ret = MultiUserManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: UnInit
 * @tc.desc: Normal testCase of MultiUserManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, UnInit_001, TestSize.Level1)
{
    int32_t ret = MultiUserManager::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: UnInit
 * @tc.desc: Normal testCase of MultiUserManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, SetCurrentForegroundUserID_001, TestSize.Level1)
{
    int32_t userId = 0;
    MultiUserManager::GetInstance().SetCurrentForegroundUserID(userId);
    EXPECT_EQ(MultiUserManager::GetInstance().foregroundUserId_, userId);
}

/*
 * @tc.name: GetCurrentForegroundUserID
 * @tc.desc: Normal testCase of MultiUserManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, GetCurrentForegroundUserID_001, TestSize.Level1)
{
    int32_t userId = 0;
    MultiUserManager::GetInstance().SetCurrentForegroundUserID(userId);
    int32_t ret = MultiUserManager::GetInstance().GetCurrentForegroundUserID();
    EXPECT_EQ(ret, MultiUserManager::GetInstance().foregroundUserId_);
}

/*
 * @tc.name: GetForegroundUserIDFromOs
 * @tc.desc: Normal testCase of MultiUserManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, GetForegroundUserIDFromOs_001, TestSize.Level1)
{
    int32_t foregroundId = 0;
    int32_t userId = 0;
    MultiUserManager::GetInstance().SetCurrentForegroundUserID(userId);
    int32_t ret = MultiUserManager::GetInstance().GetForegroundUserIDFromOs(foregroundId);
    EXPECT_EQ(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS