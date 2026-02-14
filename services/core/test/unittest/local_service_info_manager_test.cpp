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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_NE(result, DP_SUCCESS);
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
    EXPECT_EQ(result, DP_SUCCESS);
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
    EXPECT_NE(result, DP_SUCCESS);
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

/*
 * @tc.name: PutLocalServiceInfo004
 * @tc.desc: PutLocalServiceInfo with special characters in bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo004, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("test!@#$%Bundle");
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: PutLocalServiceInfo005
 * @tc.desc: PutLocalServiceInfo with unicode characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo005, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("测试应用");
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: PutLocalServiceInfo006
 * @tc.desc: PutLocalServiceInfo with long bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo006, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    std::string longBundleName(256, 'a');
    localServiceInfo.SetBundleName(longBundleName);
    localServiceInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: PutLocalServiceInfo007
 * @tc.desc: PutLocalServiceInfo with duplicate data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo007, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("duplicate.bundle");
    localServiceInfo.SetPinExchangeType(1);
    int32_t result1 = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result1, DP_CACHE_EXIST);
    int32_t result2 = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result2, DP_CACHE_EXIST);
}

/*
 * @tc.name: DeleteLocalServiceInfo004
 * @tc.desc: DeleteLocalServiceInfo non-existent record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, DeleteLocalServiceInfo004, TestSize.Level1)
{
    std::string bundleName = "nonexistent.bundle";
    int32_t pinExchangeType = 1;
    int32_t result = LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: DeleteLocalServiceInfo005
 * @tc.desc: DeleteLocalServiceInfo with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, DeleteLocalServiceInfo005, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("special!@#bundle");
    localServiceInfo.SetPinExchangeType(1);
    LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);

    std::string bundleName = "special!@#bundle";
    int32_t pinExchangeType = 1;
    int32_t result = LocalServiceInfoManager::GetInstance().DeleteLocalServiceInfo(bundleName, pinExchangeType);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: UpdateLocalServiceInfo004
 * @tc.desc: UpdateLocalServiceInfo after Put
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UpdateLocalServiceInfo004, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("update.test.bundle");
    localServiceInfo.SetPinExchangeType(1);
    LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);

    LocalServiceInfo updateInfo;
    updateInfo.SetBundleName("update.test.bundle");
    updateInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(updateInfo);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: UpdateLocalServiceInfo005
 * @tc.desc: UpdateLocalServiceInfo with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, UpdateLocalServiceInfo005, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("special更新!@#");
    localServiceInfo.SetPinExchangeType(1);
    LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);

    LocalServiceInfo updateInfo;
    updateInfo.SetBundleName("special更新!@#");
    updateInfo.SetPinExchangeType(1);
    int32_t result = LocalServiceInfoManager::GetInstance().UpdateLocalServiceInfo(updateInfo);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: GetLocalServiceInfoByBundleAndPinType004
 * @tc.desc: GetLocalServiceInfoByBundleAndPinType after Put
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, GetLocalServiceInfoByBundleAndPinType004, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("get.test.bundle");
    localServiceInfo.SetPinExchangeType(1);
    LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);

    std::string bundleName = "get.test.bundle";
    int32_t pinExchangeType = 1;
    LocalServiceInfo resultInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, resultInfo);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: GetLocalServiceInfoByBundleAndPinType005
 * @tc.desc: GetLocalServiceInfoByBundleAndPinType with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, GetLocalServiceInfoByBundleAndPinType005, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("查询测试!@#");
    localServiceInfo.SetPinExchangeType(1);
    LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);

    std::string bundleName = "查询测试!@#";
    int32_t pinExchangeType = 1;
    LocalServiceInfo resultInfo;
    int32_t result = LocalServiceInfoManager::GetInstance().GetLocalServiceInfoByBundleAndPinType(
        bundleName, pinExchangeType, resultInfo);
    EXPECT_EQ(result, DP_SUCCESS);
}

/*
 * @tc.name: Init002
 * @tc.desc: Init multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, Init002, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    int32_t result1 = localServiceInfoManager_.Init();
    EXPECT_EQ(result1, DP_SUCCESS);
    int32_t result2 = localServiceInfoManager_.Init();
    EXPECT_EQ(result2, DP_SUCCESS);
}

/*
 * @tc.name: CreateTable002
 * @tc.desc: CreateTable multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, CreateTable002, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    localServiceInfoManager_.Init();
    int32_t result1 = localServiceInfoManager_.CreateTable();
    EXPECT_EQ(result1, DP_SUCCESS);
    int32_t result2 = localServiceInfoManager_.CreateTable();
    EXPECT_EQ(result2, DP_SUCCESS);
}

/*
 * @tc.name: CreateIndex002
 * @tc.desc: CreateIndex multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, CreateIndex002, TestSize.Level1)
{
    LocalServiceInfoManager localServiceInfoManager_;
    localServiceInfoManager_.Init();
    int32_t result1 = localServiceInfoManager_.CreateIndex();
    EXPECT_EQ(result1, DP_SUCCESS);
    int32_t result2 = localServiceInfoManager_.CreateIndex();
    EXPECT_EQ(result2, DP_SUCCESS);
}

/*
 * @tc.name: PutLocalServiceInfo008
 * @tc.desc: PutLocalServiceInfo with negative pinExchangeType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo008, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("test.negative.bundle");
    localServiceInfo.SetPinExchangeType(-1);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result, DP_CACHE_EXIST);
}

/*
 * @tc.name: PutLocalServiceInfo009
 * @tc.desc: PutLocalServiceInfo with large pinExchangeType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LocalServiceInfoManagerTest, PutLocalServiceInfo009, TestSize.Level1)
{
    LocalServiceInfo localServiceInfo;
    localServiceInfo.SetBundleName("test.large.bundle");
    localServiceInfo.SetPinExchangeType(INT32_MAX);
    int32_t result = LocalServiceInfoManager::GetInstance().PutLocalServiceInfo(localServiceInfo);
    EXPECT_NE(result, DP_CACHE_EXIST);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS