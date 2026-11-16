/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "distributed_device_profile_errors.h"
#include "mock/local_switch_profile_mock.h"
#include "profile_control_utils.h"
#include "switch_profile_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedDeviceProfile {
class LocalSwitchProfileTestBase : public testing::Test {
public:
    void SetUp() override
    {
        ASSERT_EQ(TestMock::ScopedLocalSwitchProfileMock::Current(), nullptr);
    }

    void TearDown() override
    {
        EXPECT_EQ(TestMock::ScopedLocalSwitchProfileMock::Current(), nullptr);
    }
};

class SwitchProfileManagerTest : public LocalSwitchProfileTestBase {};
class ProfileControlUtilsTest : public LocalSwitchProfileTestBase {};

/*
 * @tc.name: RefreshLocalSwitchProfile_001
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, RefreshLocalSwitchProfile_001, TestSize.Level1)
{
    testing::StrictMock<TestMock::LocalSwitchProfileMock> mock;
    TestMock::ScopedLocalSwitchProfileMock scope(mock);
    EXPECT_CALL(mock, GetLocalNetworkId()).WillOnce(testing::Return(std::string()));
    EXPECT_CALL(mock, GetLocalUdid()).WillOnce(testing::Return(std::string("mockLocalUdid")));
    int32_t errCode = SwitchProfileManager::GetInstance().RefreshLocalSwitchProfile();
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshLocalSwitchProfile001
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, RefreshLocalSwitchProfile001, TestSize.Level1)
{
    testing::StrictMock<TestMock::LocalSwitchProfileMock> mock;
    TestMock::ScopedLocalSwitchProfileMock scope(mock);
    EXPECT_CALL(mock, GetLocalNetworkId()).WillOnce(testing::Return(std::string()));
    EXPECT_CALL(mock, GetLocalUdid()).WillOnce(testing::Return(std::string("mockLocalUdid")));
    std::string appId = "appId";
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->RefreshLocalSwitchProfile(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshLocalSwitchProfile003
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, RefreshLocalSwitchProfile003, TestSize.Level1)
{
    testing::StrictMock<TestMock::LocalSwitchProfileMock> mock;
    TestMock::ScopedLocalSwitchProfileMock scope(mock);
    EXPECT_CALL(mock, GetLocalNetworkId()).WillOnce(testing::Return(std::string()));
    EXPECT_CALL(mock, GetLocalUdid()).WillOnce(testing::Return(std::string("mockLocalUdid")));
    std::string appId = "appId";

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->RefreshLocalSwitchProfile(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
