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
#include "profile_cache.h"
#include "static_profile_manager.h"
using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "StaticProfileManagerTest";
}
class StaticProfileManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StaticProfileManagerTest::SetUpTestCase()
{
}

void StaticProfileManagerTest::TearDownTestCase()
{
}

void StaticProfileManagerTest::SetUp()
{
}

void StaticProfileManagerTest::TearDown()
{
}

/*
 * @tc.name: Init_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, Init_001, TestSize.Level1)
{
    int32_t errCode = StaticProfileManager::GetInstance().Init();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: UnInit_001
 * @tc.desc: UnInit
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, UnInit_001, TestSize.Level1)
{
    StaticProfileManager::GetInstance().Init();
    int32_t errCode = StaticProfileManager::GetInstance().UnInit();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: ReInit_001
 * @tc.desc: ReInit
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, ReInit_001, TestSize.Level1)
{
    StaticProfileManager::GetInstance().Init();
    int32_t errCode = StaticProfileManager::GetInstance().ReInit();
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: PutCharacteristicProfile_001
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, PutCharacteristicProfile_001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_001
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_001, TestSize.Level1)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_002
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_002, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "";
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_003
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_003, TestSize.Level1)
{
    std::string deviceId = "";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_004
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_004, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/*
 * @tc.name: GetCharacteristicProfile_005
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_005, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;
    std::string charProfileKey =
        CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + characteristicKey;
    ProfileCache::GetInstance().staticCharProfileMap_.emplace(charProfileKey, charProfile);
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/*
 * @tc.name: GetCharacteristicProfile_006
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetCharacteristicProfile_006, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;
    int32_t errCode = StaticProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(errCode, DP_SUCCESS);
}

#ifdef DEVICE_PROFILE_SWITCH_STATIC_ENABLE
/*
 * @tc.name: GetAllCharacteristicProfile_001
 * @tc.desc: GetAllCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GetAllCharacteristicProfile_001, TestSize.Level1)
{
    std::vector<CharacteristicProfile> staticCapabilityProfiles;
    int32_t errCode = StaticProfileManager::GetInstance().GetAllCharacteristicProfile(staticCapabilityProfiles);
    EXPECT_EQ(errCode, DP_SUCCESS);
}
#endif // DEVICE_PROFILE_SWITCH_STATIC_ENABLE

/*
 * @tc.name: GenerateStaticInfoProfile_001
 * @tc.desc: GenerateStaticInfoProfile
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(StaticProfileManagerTest, GenerateStaticInfoProfile_001, TestSize.Level1)
{
    CharacteristicProfile staticCapabilityProfile;
    std::unordered_map<std::string, CharacteristicProfile> staticInfoProfiles;
    int32_t errCode = StaticProfileManager::GetInstance().GenerateStaticInfoProfile(staticCapabilityProfile,
        staticInfoProfiles);
    EXPECT_EQ(errCode, DP_PARSE_STATIC_CAP_FAIL);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
