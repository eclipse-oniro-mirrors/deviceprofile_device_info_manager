/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "device_profile_dao.h"
#include "device_profile.h"
#include "device_profile_filter_options.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
const std::string TAG = "DeviceProfileDaoTest";
}
class DeviceProfileDaoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceProfileDaoTest::SetUpTestCase()
{}

void DeviceProfileDaoTest::TearDownTestCase()
{}

void DeviceProfileDaoTest::SetUp()
{}

void DeviceProfileDaoTest::TearDown()
{}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, Init001, TestSize.Level1)
{
    int32_t result = DeviceProfileDao::GetInstance().Init();
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UnInit001, TestSize.Level1)
{
    int32_t result = DeviceProfileDao::GetInstance().UnInit();
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: Init002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UnInit002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    int32_t result = DeviceProfileDao::GetInstance().UnInit();
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: UnInit002
 * @tc.desc: UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UnInit003, TestSize.Level1)
{
    int32_t result = DeviceProfileDao::GetInstance().UnInit();
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: PutDeviceProfile001
 * @tc.desc: PutDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, PutDeviceProfile001, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    int32_t result = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().Init();
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    EXPECT_EQ(result, DP_PUT_TRUST_DEVICE_PROFILE_FAIL);
}

/*
 * @tc.name: GetDeviceProfiles003
 * @tc.desc: GetDeviceProfiles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, PutDeviceProfile003, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    int ret = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_EQ(ret, DP_PUT_TRUST_DEVICE_PROFILE_FAIL);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: GetDeviceProfiles001
 * @tc.desc: GetDeviceProfiles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, GetDeviceProfiles001, TestSize.Level1)
{
    DeviceProfileFilterOptions filterOptions;
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, deviceProfiles);
    EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
}

/*
 * @tc.name: GetDeviceProfiles002
 * @tc.desc: GetDeviceProfiles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, GetDeviceProfiles002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfileFilterOptions filterOptions;
    filterOptions.SetUserId(5);
    filterOptions.SetDeviceIds({"deviceId"});
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, deviceProfiles);
    EXPECT_EQ(result, DP_NOT_FIND_DATA);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: GetDeviceProfiles003
 * @tc.desc: GetDeviceProfiles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, GetDeviceProfiles003, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileFilterOptions filterOptions;
    filterOptions.SetUserId(1);
    filterOptions.SetDeviceIds({"deviceId"});
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, deviceProfiles);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: DeleteDeviceProfile001
 * @tc.desc: DeleteDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, DeleteDeviceProfile001, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    int32_t result = DeviceProfileDao::GetInstance().DeleteDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: DeleteDeviceProfile002
 * @tc.desc: DeleteDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, DeleteDeviceProfile002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    int32_t result = DeviceProfileDao::GetInstance().DeleteDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_DELETE_TRUST_DEVICE_PROFILE_FAIL);
}

/*
 * @tc.name: UpdateDeviceProfile001
 * @tc.desc: UpdateDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UpdateDeviceProfile001, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    deviceProfile.SetSubProductId("SubProductId");
    int32_t result = DeviceProfileDao::GetInstance().UpdateDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: UpdateDeviceProfile001
 * @tc.desc: UpdateDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UpdateDeviceProfile002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId");
    deviceProfile.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    deviceProfile.SetSubProductId("SubProductId");
    int32_t result = DeviceProfileDao::GetInstance().UpdateDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL);
}

/*
 * @tc.name: CreateTable001
 * @tc.desc: CreateTable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateTable001, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    int32_t result = DeviceProfileDao::GetInstance().CreateTable();
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: CreateTable002
 * @tc.desc: CreateTable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateTable002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    ProfileDataRdbAdapter::GetInstance().UnInit();
    int32_t result = DeviceProfileDao::GetInstance().CreateTable();
    EXPECT_EQ(result, DP_CREATE_TABLE_FAIL);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: CreateIndex001
 * @tc.desc: CreateIndex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateIndex001, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    ProfileDataRdbAdapter::GetInstance().UnInit();
    int32_t result = DeviceProfileDao::GetInstance().CreateIndex();
    EXPECT_EQ(result, DP_CREATE_UNIQUE_INDEX_FAIL);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: CreateIndex002
 * @tc.desc: CreateIndex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateIndex002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    int32_t result = DeviceProfileDao::GetInstance().CreateIndex();
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: CreateQuerySqlAndCondition001
 * @tc.desc: CreateQuerySqlAndCondition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateQuerySqlAndCondition001, TestSize.Level1)
{
    DeviceProfileFilterOptions filterOptions;
    std::string sql = "";
    std::vector<ValueObject> condition;
    DeviceProfileDao::GetInstance().CreateQuerySqlAndCondition(filterOptions, sql, condition);
    EXPECT_NE(sql, "");
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: CreateQuerySqlAndCondition001
 * @tc.desc: CreateQuerySqlAndCondition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, CreateQuerySqlAndCondition002, TestSize.Level1)
{
    DeviceProfileFilterOptions filterOptions;
    std::vector<int32_t> deviceProfileIds;
    deviceProfileIds.emplace_back(3);
    filterOptions.SetDeviceProfileIds(deviceProfileIds);
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back("deviceId1");
    filterOptions.SetDeviceIds(deviceIds);
    filterOptions.SetUserId(1);
    filterOptions.SetAccountId("AccountId");
    std::vector<std::string> wiseDeviceIds;
    wiseDeviceIds.emplace_back("WiseDeviceIds");
    filterOptions.SetWiseDeviceIds(wiseDeviceIds);
    std::string sql = "";
    std::vector<ValueObject> condition;
    DeviceProfileDao::GetInstance().CreateQuerySqlAndCondition(filterOptions, sql, condition);
    EXPECT_NE(sql, "");
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: PutDeviceProfile002
 * @tc.desc: PutDeviceProfile with empty deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, PutDeviceProfile002, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("");
    deviceProfile.SetUserId(1);
    int32_t result = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(result, DP_CACHE_EXIST);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: PutDeviceProfile004
 * @tc.desc: PutDeviceProfile with long deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, PutDeviceProfile004, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    std::string longDeviceId(256, 'a');
    deviceProfile.SetDeviceId(longDeviceId);
    deviceProfile.SetUserId(1);
    int32_t result = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: PutDeviceProfile005
 * @tc.desc: PutDeviceProfile with zero userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, PutDeviceProfile005, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("deviceId005");
    deviceProfile.SetUserId(0);
    int32_t result = DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile);
    DeviceProfileDao::GetInstance().UnInit();
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: GetDeviceProfiles004
 * @tc.desc: GetDeviceProfiles with empty filter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, GetDeviceProfiles004, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfileFilterOptions filterOptions;
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, deviceProfiles);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: GetDeviceProfiles005
 * @tc.desc: GetDeviceProfiles with multiple deviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, GetDeviceProfiles005, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile1;
    deviceProfile1.SetDeviceId("device001");
    deviceProfile1.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile1);
    DeviceProfile deviceProfile2;
    deviceProfile2.SetDeviceId("device002");
    deviceProfile2.SetUserId(1);
    DeviceProfileDao::GetInstance().PutDeviceProfile(deviceProfile2);

    DeviceProfileFilterOptions filterOptions;
    filterOptions.SetUserId(1);
    filterOptions.SetDeviceIds({"device001", "device002"});
    std::vector<DeviceProfile> deviceProfiles;
    int32_t result = DeviceProfileDao::GetInstance().GetDeviceProfiles(filterOptions, deviceProfiles);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: DeleteDeviceProfile003
 * @tc.desc: DeleteDeviceProfile with empty deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, DeleteDeviceProfile003, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("");
    deviceProfile.SetUserId(1);
    int32_t result = DeviceProfileDao::GetInstance().DeleteDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: DeleteDeviceProfile004
 * @tc.desc: DeleteDeviceProfile non-existent record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, DeleteDeviceProfile004, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("nonexistent");
    deviceProfile.SetUserId(1);
    int32_t result = DeviceProfileDao::GetInstance().DeleteDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: UpdateDeviceProfile003
 * @tc.desc: UpdateDeviceProfile with empty deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UpdateDeviceProfile003, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("");
    deviceProfile.SetUserId(1);
    deviceProfile.SetSubProductId("SubProductId");
    int32_t result = DeviceProfileDao::GetInstance().UpdateDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}

/*
 * @tc.name: UpdateDeviceProfile004
 * @tc.desc: UpdateDeviceProfile non-existent record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileDaoTest, UpdateDeviceProfile004, TestSize.Level1)
{
    DeviceProfileDao::GetInstance().Init();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("nonexistent");
    deviceProfile.SetUserId(1);
    deviceProfile.SetSubProductId("SubProductId");
    int32_t result = DeviceProfileDao::GetInstance().UpdateDeviceProfile(deviceProfile);
    EXPECT_EQ(result, DP_SUCCESS);
    DeviceProfileDao::GetInstance().UnInit();
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
