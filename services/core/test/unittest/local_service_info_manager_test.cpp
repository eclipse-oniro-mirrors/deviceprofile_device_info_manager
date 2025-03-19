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

#include "local_service_info_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
const std::string TAG = "LocalServiceInfoManagerTest";
}
class LocalServiceInfoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LocalServiceInfoManagerTest::SetUpTestCase()
{}

void LocalServiceInfoManagerTest::TearDownTestCase()
{}

void LocalServiceInfoManagerTest::SetUp()
{}

void LocalServiceInfoManagerTest::TearDown()
{}

/*
 * @tc.name: Init001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, Init001, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    int32_t result = localServiceInfoManager_.Init();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: UnInit001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UnInit001, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    int32_t result = localServiceInfoManager_.Init();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: CreateTable001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, CreateTable001, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    int32_t result = localServiceInfoManager_.CreateTable();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: CreateIndex001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, CreateIndex001, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    int32_t result = localServiceInfoManager_.CreateIndex();
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: PutLocalServiceInfo001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: PutLocalServiceInfo002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo002, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("testBundle");
    localServiceInfo.SetPinExchangeType(0);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: PutLocalServiceInfo003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo003, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("testBundle");
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: DeleteLocalServiceInfo001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, DeleteLocalServiceInfo001, TestSize.Level1)
{
    std::string bundleName;
    int32_t pinExchangeType = 1;
    int32_t result = LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: DeleteLocalServiceInfo002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, DeleteLocalServiceInfo002, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    int32_t pinExchangeType = 0;
    int32_t result = LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: DeleteLocalServiceInfo003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, DeleteLocalServiceInfo003, TestSize.Level1)
{
    std::string bundleName = "testBundle";
    int32_t pinExchangeType = 1;
    int32_t result = LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(result, 0);
}

/*
 * @tc.name: UpdateLocalServiceInfo001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UpdateLocalServiceInfo001, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: UpdateLocalServiceInfo002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UpdateLocalServiceInfo002, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("com.test.app");
    localServiceInfo.SetPinExchangeType(0);
    int32_t result = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: UpdateLocalServiceInfo003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UpdateLocalServiceInfo003, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("com.test.app");
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(localServiceInfo);
    EXPECT_EQ(result, DP_NOT_FIND_DATA);
}

/*
 * @tc.name: GetLocalServiceInfoByBundleAndPinType001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, GetLocalServiceInfoByBundleAndPinType001, TestSize.Level1)
{
    std::string bundleName;
    int32_t pinExchangeType = 1;
    LocalServiceInfo localServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalServiceInfoByBundleAndPinType002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, GetLocalServiceInfoByBundleAndPinType002, TestSize.Level1)
{
    std::string bundleName = "com.test.app";
    int32_t pinExchangeType = 0;
    LocalServiceInfo localServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, localServiceInfo);
    EXPECT_EQ(result, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetLocalServiceInfoByBundleAndPinType003
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, GetLocalServiceInfoByBundleAndPinType003, TestSize.Level1)
{
    std::string bundleName = "com.test.app";
    int32_t pinExchangeType = 1;
    LocalServiceInfo localServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, localServiceInfo);
    EXPECT_EQ(result, DP_NOT_FIND_DATA);
}

/*
 * @tc.name: ConvertToLocalServiceInfo001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, ConvertToLocalServiceInfo001, TestSize.Level1)
{
    LocalServiceInfo LocalServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().ConvertToLocalServiceInfo(nullptr, LocalServiceInfo);
    EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
}

/*
 * @tc.name: ConvertToLocalServiceInfo002
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, ConvertToLocalServiceInfo002, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet;
    LocalServiceInfo LocalServiceInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().ConvertToLocalServiceInfo(resultSet, LocalServiceInfo);
    EXPECT_EQ(result, DP_GET_RESULTSET_FAIL);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS