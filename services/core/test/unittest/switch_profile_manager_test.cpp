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
#include "event_handler_factory.h"
#include "switch_profile_manager.h"
using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "SwitchProfileManagerTest";
}
class SwitchProfileManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SwitchProfileManagerTest::SetUpTestCase()
{
}

void SwitchProfileManagerTest::TearDownTestCase()
{
}

void SwitchProfileManagerTest::SetUp()
{
}

void SwitchProfileManagerTest::TearDown()
{
}

/*
 * @tc.name: Init_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, Init_001, TestSize.Level1)
{
    int32_t errCode = SwitchProfileManager::GetInstance().Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: UnInit_001
 * @tc.desc: UnInit
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, UnInit_001, TestSize.Level1)
{
    SwitchProfileManager::GetInstance().Init();
    int32_t errCode = SwitchProfileManager::GetInstance().UnInit();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: ReInit_001
 * @tc.desc: ReInit
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, ReInit_001, TestSize.Level1)
{
    SwitchProfileManager::GetInstance().Init();
    int32_t errCode = SwitchProfileManager::GetInstance().ReInit();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: PutCharacteristicProfile_001
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, PutCharacteristicProfile_001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    int32_t errCode = SwitchProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: PutCharacteristicProfileBatch_001
 * @tc.desc: PutCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, PutCharacteristicProfileBatch_001, TestSize.Level1)
{
    std::vector<CharacteristicProfile> charProfiles;
    int32_t errCode = SwitchProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_001
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, GetCharacteristicProfile_001, TestSize.Level1)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    CharacteristicProfile charProfile;
    int32_t errCode = SwitchProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: RefreshLocalSwitchProfile_001
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SwitchProfileManagerTest, RefreshLocalSwitchProfile_001, TestSize.Level1)
{
    int32_t errCode = SwitchProfileManager::GetInstance().RefreshLocalSwitchProfile();
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS