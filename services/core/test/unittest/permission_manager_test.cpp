/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "profile_utils.h"
#include "permission_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "PermissionManagerTest";
}
class PermissionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PermissionManagerTest::SetUpTestCase()
{
    int32_t ret = PermissionManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

void PermissionManagerTest::TearDownTestCase()
{
    int32_t ret = PermissionManager::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}

void PermissionManagerTest::SetUp()
{
}

void PermissionManagerTest::TearDown()
{
}

/*
 * @tc.name: IsCallerTrust_001
 * @tc.desc: Normal testCase of PermissionManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, IsCallerTrust_001, TestSize.Level1)
{
    PermissionManager::GetInstance().GetCallerProcName();

    bool ret = PermissionManager::GetInstance().IsCallerTrust(PUT_ACCESS_CONTROL_PROFILE);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: CheckCallerPermission_001
 * @tc.desc: Normal testCase of PermissionManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, CheckCallerPermission_001, TestSize.Level1)
{
    bool ret = PermissionManager::GetInstance().CheckCallerPermission();
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: CheckCallerSyncPermission_001
 * @tc.desc: Normal testCase of PermissionManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(PermissionManagerTest, CheckCallerSyncPermission_001, TestSize.Level1)
{
    bool ret = PermissionManager::GetInstance().CheckCallerSyncPermission();
    EXPECT_EQ(ret, false);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS