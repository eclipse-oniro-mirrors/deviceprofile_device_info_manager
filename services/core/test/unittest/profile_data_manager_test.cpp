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

#include "profile_data_manager.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
const std::string TAG = "ProfileDataManagerTest";
}
class ProfileDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileDataManagerTest::SetUpTestCase()
{}

void ProfileDataManagerTest::TearDownTestCase()
{}

void ProfileDataManagerTest::SetUp()
{}

void ProfileDataManagerTest::TearDown()
{}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, Init001, TestSize.Level1)
{
    ProfileDataManager profileDataManager_;
    int32_t result = profileDataManager_.Init();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: UnInit001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, UnInit001, TestSize.Level1)
{
    ProfileDataManager profileDataManager_;
    int32_t result = profileDataManager_.UnInit();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, PutDeviceProfile_001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetDeviceId("anything" + SLASHES + "123" + SEPARATOR + "abc");
    int32_t result = ProfileDataManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_INVALID_PARAMS);
}

/*
 * @tc.name: PutDeviceProfile_002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, PutDeviceProfile_002, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    int32_t result = ProfileDataManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_INVALID_PARAMS);
}

/*
 * @tc.name: FilterInvaildSymbol_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_001, TestSize.Level1)
{
    std::string str = "";
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(str);
    EXPECT_EQ(result, false);
}

/*
 * @tc.name: FilterInvaildSymbol_002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_002, TestSize.Level1)
{
    std::string longString(MAX_STRING_LEN + 1, 'A');
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(longString);
    EXPECT_EQ(result, false);
}

/*
 * @tc.name: FilterInvaildSymbol_003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_003, TestSize.Level1)
{
    std::string str = SEPARATOR;
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(str);
    EXPECT_EQ(result, false);
}

/*
 * @tc.name: FilterInvaildSymbol_004
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_004, TestSize.Level1)
{
    std::string str = SLASHES;
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(str);
    EXPECT_EQ(result, false);
}

/*
 * @tc.name: FilterInvaildSymbol_005
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_005, TestSize.Level1)
{
    std::string str = "abcdef";
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(str);
    EXPECT_EQ(result, false);
}

/*
 * @tc.name: FilterInvaildSymbol_006
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, FilterInvaildSymbol_006, TestSize.Level1)
{
    std::string str = "abc" + SEPARATOR + "xyz" + SLASHES + "123";
    int32_t result = ProfileDataManager::GetInstance().FilterInvaildSymbol(str);
    EXPECT_EQ(result, true);
}

/*
 * @tc.name: PutDeviceProfileBatch_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, PutDeviceProfileBatch_001, TestSize.Level1)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = ProfileDataManager::GetInstance().PutDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: PutDeviceProfileBatch_002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, PutDeviceProfileBatch_002, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    std::vector<DeviceProfile> deviceProfiles = {deviceProfile};
    int32_t result = ProfileDataManager::GetInstance().PutDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(result, 98566144);
}

/*
 * @tc.name: GetDeviceProfiles_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceProfiles_001, TestSize.Level1)
{
    DeviceProfileFilterOptions options;
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceProfiles(options, deviceProfiles);
    EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
}

/*
 * @tc.name: DeleteDeviceProfileBatch_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, DeleteDeviceProfileBatch_001, TestSize.Level1)
{
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = ProfileDataManager::GetInstance().DeleteDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: DeleteDeviceProfileBatch_002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, DeleteDeviceProfileBatch_002, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    std::vector<DeviceProfile> deviceProfiles = {deviceProfile};
    int32_t result = ProfileDataManager::GetInstance().DeleteDeviceProfileBatch(deviceProfiles);
    EXPECT_EQ(result, DP_DELETE_TRUST_DEVICE_PROFILE_FAIL);
}

/*
 * @tc.name: GetDeviceIconInfos_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_001, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetDeviceIconInfos_002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_002, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    filterOptions.SetSubProductId("subId");
    filterOptions.SetImageType("imageType");
    filterOptions.SetSpecName("specName");
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetDeviceIconInfos_003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_003, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    filterOptions.SetProductIds({"productId"});
    filterOptions.SetImageType("imageType");
    filterOptions.SetSpecName("specName");
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetDeviceIconInfos_004
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_004, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    filterOptions.SetProductIds({"productId"});
    filterOptions.SetSubProductId("subId");
    filterOptions.SetSpecName("specName");
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetDeviceIconInfos_005
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_005, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    filterOptions.SetProductIds({"productId"});
    filterOptions.SetSubProductId("subId");
    filterOptions.SetImageType("imageType");
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetDeviceIconInfos_006
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileDataManagerTest, GetDeviceIconInfos_006, TestSize.Level1)
{
    DeviceIconInfoFilterOptions filterOptions;
    filterOptions.SetProductIds({"productId"});
    filterOptions.SetSubProductId("subId");
    filterOptions.SetImageType("imageType");
    filterOptions.SetSpecName("specName");
    std::vector<DeviceIconInfo> deviceIconInfos;
    int32_t result = ProfileDataManager::GetInstance().GetDeviceIconInfos(filterOptions, deviceIconInfos);
    EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS