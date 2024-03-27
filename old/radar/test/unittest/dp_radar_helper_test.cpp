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
namespace DeviceProfile {
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

HWTEST_F(DpRadarHelperTest, ReportCheckDpSa_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportCheckDpSa(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportCheckDpSa_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_CANCEL);
    bool res = DpRadarHelper::GetInstance().ReportCheckDpSa(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportLoadDpSa_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportLoadDpSa(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportLoadDpSa_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportLoadDpSa(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportLoadDpSaCb_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_CANCEL);
    bool res = DpRadarHelper::GetInstance().ReportLoadDpSaCb(info);
    EXPECT_EQ(res, true);
}
HWTEST_F(DpRadarHelperTest, ReportLoadDpSaCb_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportLoadDpSaCb(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSaCheckAuth_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSaCheckAuth(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSaCheckAuth_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportSaCheckAuth(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportGetData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportGetData(info);
    EXPECT_EQ(res, true);
}
HWTEST_F(DpRadarHelperTest, ReportGetData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportGetData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportAddData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportAddData(info);
    EXPECT_EQ(res, true);
}
HWTEST_F(DpRadarHelperTest, ReportAddData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportAddData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportDeleteData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportDeleteData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportDeleteData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportDeleteData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSubscribeData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSubscribeData(info);
    EXPECT_EQ(res, true);
}
HWTEST_F(DpRadarHelperTest, ReportSubscribeData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportSubscribeData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportNotifyDataChange_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportNotifyDataChange(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportUnsbscribeData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportUnsbscribeData(info);
    EXPECT_EQ(res, true);
}
HWTEST_F(DpRadarHelperTest, ReportUnsbscribeData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportUnsbscribeData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSyncData_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_IDLE);
    bool res = DpRadarHelper::GetInstance().ReportSyncData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSyncData_002, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSyncData(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, ReportSyncDataCb_001, testing::ext::TestSize.Level0)
{
    struct RadarInfo info = { 0 };
    info.stageRes = static_cast<int32_t>(StageRes::STAGE_SUCC);
    bool res = DpRadarHelper::GetInstance().ReportSyncDataCb(info);
    EXPECT_EQ(res, true);
}

HWTEST_F(DpRadarHelperTest, GetAnonyUdid_001, testing::ext::TestSize.Level0)
{
    std::string udid = "";
    std::string res = DpRadarHelper::GetInstance().GetAnonyUdid(udid);
    EXPECT_EQ(res, "");

    udid = "1234567890abcdef";
    res = DpRadarHelper::GetInstance().GetAnonyUdid(udid);
    EXPECT_EQ(res, "12345**bcdef");
}
} // namespace DeviceProfile
} // namespace OHOS
