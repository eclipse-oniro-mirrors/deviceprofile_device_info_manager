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

#include "dp_radar_helper_test.h"
#include "dp_radar_helper.h"

namespace OHOS {
namespace DistributedDeviceProfile {
void DpRadarHelperTest::SetUp()
{
}

void DpRadarHelperTest::TearDown()
{
}

void DpRadarHelperTest::SetUpTestCase()
{
}

void DpRadarHelperTest::TearDownTestCase()
{
}

HWTEST_F(DpRadarHelperTest, ReportPutACProfile_001, testing::ext::TestSize.Level0)
{
    AccessControlProfile accessControlProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportPutAclProfile(errCode, accessControlProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportPutAclProfile(errCode, accessControlProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportUpdateACProfile_001, testing::ext::TestSize.Level0)
{
    AccessControlProfile accessControlProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportUpdateAclProfile(errCode, accessControlProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportUpdateAclProfile(errCode, accessControlProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetTrustProfile_001, testing::ext::TestSize.Level0)
{
    TrustDeviceProfile trustDeviceProfile;
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetTrustProfile(errCode, deviceId, trustDeviceProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetTrustProfile(errCode, deviceId, trustDeviceProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetAllTrustProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetAllTrustProfile(errCode, trustDeviceProfiles);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetAllTrustProfile(errCode, trustDeviceProfiles);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetACProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetAclProfile(errCode, accessControlProfiles);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetAclProfile(errCode, accessControlProfiles);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetAllACProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetAllAclProfile(errCode, accessControlProfiles);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetAllAclProfile(errCode, accessControlProfiles);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportDeleteACProfile_001, testing::ext::TestSize.Level0)
{
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportDeleteAclProfile(errCode);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportDeleteAclProfile(errCode);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportPutServiceProfile_001, testing::ext::TestSize.Level0)
{
    ServiceProfile serviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportPutServiceProfile(errCode, serviceProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportPutServiceProfile(errCode, serviceProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportPutServiceProfileBatch_001, testing::ext::TestSize.Level0)
{
    std::vector<ServiceProfile> serviceProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(errCode, serviceProfiles);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(errCode, serviceProfiles);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportPutChProfile_001, testing::ext::TestSize.Level0)
{
    CharacteristicProfile characteristicProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportPutCharProfile(errCode, characteristicProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportPutCharProfile(errCode, characteristicProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportPutChProfileBatch_001, testing::ext::TestSize.Level0)
{
    std::vector<CharacteristicProfile> characteristicProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportPutCharProfileBatch(errCode, characteristicProfiles);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportPutCharProfileBatch(errCode, characteristicProfiles);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetDeviceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    DeviceProfile deviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetDeviceProfile(errCode, deviceId, deviceProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetDeviceProfile(errCode, deviceId, deviceProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetServiceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    ServiceProfile serviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetServiceProfile(errCode, deviceId, serviceProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetServiceProfile(errCode, deviceId, serviceProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetChProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    CharacteristicProfile characteristicProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetCharProfile(errCode, deviceId, characteristicProfile);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportGetCharProfile(errCode, deviceId, characteristicProfile);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportDeleteServiceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportDeleteServiceProfile(errCode, deviceId);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportDeleteServiceProfile(errCode, deviceId);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportDeleteChProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportDeleteCharProfile(errCode, deviceId);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportDeleteCharProfile(errCode, deviceId);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSubscribeDeviceProfile_001, testing::ext::TestSize.Level0)
{
    SubscribeInfo subscribeInfo;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(errCode, subscribeInfo);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(errCode, subscribeInfo);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportUnSubscribeDeviceProfile_001, testing::ext::TestSize.Level0)
{
    SubscribeInfo subscribeInfo;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(errCode, subscribeInfo);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(errCode, subscribeInfo);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSyncDeviceProfile_001, testing::ext::TestSize.Level0)
{
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSyncDeviceProfile(errCode);
    EXPECT_EQ(res, true);

    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    res = DpRadarHelper::GetInstance().ReportSyncDeviceProfile(errCode);
    EXPECT_EQ(res, true);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
