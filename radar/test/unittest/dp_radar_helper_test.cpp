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
    DpRadarHelper::GetInstance().ReportPutAclProfile(errCode, accessControlProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportPutAclProfile(errCode, accessControlProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportUpdateACProfile_001, testing::ext::TestSize.Level0)
{
    AccessControlProfile accessControlProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportUpdateAclProfile(errCode, accessControlProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportUpdateAclProfile(errCode, accessControlProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetTrustProfile_001, testing::ext::TestSize.Level0)
{
    TrustDeviceProfile trustDeviceProfile;
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetTrustProfile(errCode, deviceId, trustDeviceProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetTrustProfile(errCode, deviceId, trustDeviceProfile);

    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetAllTrustProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetAllTrustProfile(errCode, trustDeviceProfiles);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetAllTrustProfile(errCode, trustDeviceProfiles);
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetACProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetAclProfile(errCode, accessControlProfiles);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetAclProfile(errCode, accessControlProfiles);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetAllACProfile_001, testing::ext::TestSize.Level0)
{
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetAllAclProfile(errCode, accessControlProfiles);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetAllAclProfile(errCode, accessControlProfiles);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportDeleteACProfile_001, testing::ext::TestSize.Level0)
{
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportDeleteAclProfile(errCode);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportDeleteAclProfile(errCode);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportPutServiceProfile_001, testing::ext::TestSize.Level0)
{
    ServiceProfile serviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportPutServiceProfile(errCode, serviceProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportPutServiceProfile(errCode, serviceProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportPutServiceProfileBatch_001, testing::ext::TestSize.Level0)
{
    std::vector<ServiceProfile> serviceProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(errCode, serviceProfiles);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportPutServiceProfileBatch(errCode, serviceProfiles);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportPutChProfile_001, testing::ext::TestSize.Level0)
{
    CharacteristicProfile characteristicProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportPutCharProfile(errCode, characteristicProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportPutCharProfile(errCode, characteristicProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportPutChProfileBatch_001, testing::ext::TestSize.Level0)
{
    std::vector<CharacteristicProfile> characteristicProfiles;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportPutCharProfileBatch(errCode, characteristicProfiles);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportPutCharProfileBatch(errCode, characteristicProfiles);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetDeviceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    DeviceProfile deviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetDeviceProfile(errCode, deviceId, deviceProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetDeviceProfile(errCode, deviceId, deviceProfile);

    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetServiceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    ServiceProfile serviceProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetServiceProfile(errCode, deviceId, serviceProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetServiceProfile(errCode, deviceId, serviceProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportGetChProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    CharacteristicProfile characteristicProfile;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportGetCharProfile(errCode, deviceId, characteristicProfile);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportGetCharProfile(errCode, deviceId, characteristicProfile);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportDeleteServiceProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportDeleteServiceProfile(errCode, deviceId);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportDeleteServiceProfile(errCode, deviceId);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportDeleteChProfile_001, testing::ext::TestSize.Level0)
{
    std::string deviceId = "";
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportDeleteCharProfile(errCode, deviceId);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportDeleteCharProfile(errCode, deviceId);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportSubscribeDeviceProfile_001, testing::ext::TestSize.Level0)
{
    SubscribeInfo subscribeInfo;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(errCode, subscribeInfo);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportSubscribeDeviceProfile(errCode, subscribeInfo);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportUnSubscribeDeviceProfile_001, testing::ext::TestSize.Level0)
{
    SubscribeInfo subscribeInfo;
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(errCode, subscribeInfo);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportUnSubscribeDeviceProfile(errCode, subscribeInfo);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportSyncDeviceProfile_001, testing::ext::TestSize.Level0)
{
    int32_t errCode = static_cast<int32_t>(StageRes::STAGE_SUCC);
    DpRadarHelper::GetInstance().ReportSyncDeviceProfile(errCode);
    errCode = static_cast<int32_t>(StageRes::STAGE_FAIL);
    DpRadarHelper::GetInstance().ReportSyncDeviceProfile(errCode);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, ReportNotifyProfileChange_001, testing::ext::TestSize.Level0)
{
    int32_t code = ProfileType::DEVICE_PROFILE * ChangeType::ADD;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::DEVICE_PROFILE * ChangeType::UPDATE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::DEVICE_PROFILE * ChangeType::DELETE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::SERVICE_PROFILE * ChangeType::ADD;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::SERVICE_PROFILE * ChangeType::UPDATE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::SERVICE_PROFILE * ChangeType::DELETE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::CHAR_PROFILE * ChangeType::ADD;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::CHAR_PROFILE * ChangeType::UPDATE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    code = ProfileType::CHAR_PROFILE * ChangeType::DELETE;
    DpRadarHelper::GetInstance().ReportNotifyProfileChange(code);
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, GetPeerUdidList_001, testing::ext::TestSize.Level0)
{
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    std::string res = DpRadarHelper::GetInstance().GetPeerUdidList(trustDeviceProfiles);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, GetAnonyUdid_001, testing::ext::TestSize.Level0)
{
    std::string udid = "";
    std::string res = DpRadarHelper::GetInstance().GetAnonyUdid(udid);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, GetAnonyUdid_002, testing::ext::TestSize.Level0)
{
    std::string udid = "123456";
    std::string res = DpRadarHelper::GetInstance().GetAnonyUdid(udid);
    EXPECT_EQ(res, "");
}

HWTEST_F(DpRadarHelperTest, GetAnonyUdid_003, testing::ext::TestSize.Level0)
{
    std::string udid = "12345678910";
    std::string res = DpRadarHelper::GetInstance().GetAnonyUdid(udid);
    EXPECT_EQ(res, "12345**78910");
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
