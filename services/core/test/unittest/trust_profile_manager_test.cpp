/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#define private   public
#define protected public
#include "profile_utils.h"
#include "trust_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "rdb_open_callback.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace std;
namespace {
    const std::string TAG = "TrustProfileManagerTest";
}
class TrustProfileManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int ResultSize(std::shared_ptr<ResultSet>& resultSet);
};

void TrustProfileManagerTest::SetUpTestCase()
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        TrustProfileManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

void TrustProfileManagerTest::TearDownTestCase()
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        TrustProfileManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::
        TrustProfileManager::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}

void TrustProfileManagerTest::SetUp()
{
}

void TrustProfileManagerTest::TearDown()
{
}

int TrustProfileManagerTest::ResultSize(std::shared_ptr<ResultSet> &resultSet)
{
    if (resultSet->GoToFirstRow() != E_OK) {
        return 0;
    }
    int count;
    resultSet->GetRowCount(count);
    return count;
}

/*
 * @tc.name: GetAllTrustDeviceProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAllTrustDeviceProfile_002, TestSize.Level1)
{
    std::vector<TrustDeviceProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllTrustDeviceProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAllAccessControlProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAllAccessControlProfile_002, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllAccessControlProfile(profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_013
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_013, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, "111", profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    std::map<std::string, std::string> parms;
    parms.insert({{"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"bundleName", "b1"}, {"bindtype", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accountId", "b1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    int32_t status;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetResultStatus("1111", status);
    EXPECT_NE(ret, DP_SUCCESS);

    shared_ptr<ResultSet> resultRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetResultSet("122", { ValueObject(1) });
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(resultRet, 1, 1,  profile);
    EXPECT_NE(ret, DP_SUCCESS);

    AccessControlProfile aclProfile;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfileCheck(aclProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(resultRet, 1, 1,  profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_014
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_014, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"accesserDeviceId", "9999"}, {"accesserUserId", "101"}, {"accesserTokenId", "123"},
        {"accesseeDeviceId", "6666"}, {"accesseeUserId", "101"}, {"accesseeTokenId", "123"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "9999"}, {"accesserUserId", "101"}, {"accesserTokenId", "123"},
        {"accesseeDeviceId", "6666"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: Convert_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, Convert_001, TestSize.Level1)
{
    shared_ptr<ResultSet> resultRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetResultSet("122", { ValueObject(1) });
    TrustDeviceProfile trustProfile;
    int32_t ret = ProfileUtils::ConvertToTrustDeviceProfile(resultRet, trustProfile);
    EXPECT_NE(ret, DP_SUCCESS);

    Accessee accessee;
    ret = ProfileUtils::ConvertToAccessee(resultRet, accessee);
    EXPECT_NE(ret, DP_SUCCESS);

    Accesser accesser;
    ret = ProfileUtils::ConvertToAccesser(resultRet, accesser);
    EXPECT_NE(ret, DP_SUCCESS);

    AccessControlProfile profile;
    ret = ProfileUtils::ConvertToAccessControlProfile(resultRet, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    AccessControlProfile oldProfile;
    profile.SetAccessControlId(666);
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAclCheck(profile, oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);

    profile.SetTrustDeviceId("4546456");
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAclCheck(profile, oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteTrustDeviceProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteTrustDeviceProfile_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteTrustDeviceProfile("12215656");
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_001, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer1");
    accesser.SetAccesserUserId(11);
    accesser.SetAccesserAccountId("a1");
    accesser.SetAccesserTokenId(111);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("h1");
    accesser.SetAccesserBindLevel(1);
    accesser.SetAccesserDeviceName("70");
    accesser.SetAccesserServiceName("paste");
    accesser.SetAccesserCredentialId(66666);
    accesser.SetAccesserStatus(0);
    accesser.SetAccesserSessionKeyId(88888);
    accesser.SetAccesserSKTimeStamp(99999);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee1");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("a1");
    accessee.SetAccesseeTokenId(222);
    accessee.SetAccesseeBundleName("bb1");
    accessee.SetAccesseeHapSignature("h1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutTrustDeviceProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutTrustDeviceProfile_001, TestSize.Level1)
{
    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    TrustDeviceProfile trustProfile;
    ProfileUtils::ConvertToTrustDeviceProfile(profile, trustProfile);
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutTrustDeviceProfile(trustProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_011
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_011, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer11");
    accesser.SetAccesserUserId(11);
    accesser.SetAccesserAccountId("a11");
    accesser.SetAccesserTokenId(111);
    accesser.SetAccesserBundleName("b11");
    accesser.SetAccesserHapSignature("h11");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee11");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("a11");
    accessee.SetAccesseeTokenId(222);
    accessee.SetAccesseeBundleName("bb11");
    accessee.SetAccesseeHapSignature("h11");
    accessee.SetAccesseeBindLevel(1);
    accessee.SetAccesseeDeviceName("70");
    accessee.SetAccesseeServiceName("paste");
    accessee.SetAccesseeCredentialId(66666);
    accessee.SetAccesseeStatus(0);
    accessee.SetAccesseeSessionKeyId(88888);
    accessee.SetAccesseeSKTimeStamp(99999);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_002, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer2");
    accesser.SetAccesserUserId(33);
    accesser.SetAccesserAccountId("a2");
    accesser.SetAccesserTokenId(333);
    accesser.SetAccesserBundleName("b2");
    accesser.SetAccesserHapSignature("h2");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("123456");
    accessee.SetAccesseeUserId(44);
    accessee.SetAccesseeAccountId("a2");
    accessee.SetAccesseeTokenId(444);
    accessee.SetAccesseeBundleName("bb2");
    accessee.SetAccesseeHapSignature("h2");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(1);
    profile.SetValidPeriod(99);
    profile.SetLastAuthTime(66);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_015
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_015, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "44"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}, {"accesseeUserId", "44"}, {"accesseeTokenId", "444"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}, {"accesseeUserId", "55"}, {"accesseeTokenId", "444"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "acee22"}, {"accesseeUserId", "44"}, {"accesseeTokenId", "555"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "444"},
        {"accesseeDeviceId", "123456"}, {"accesseeUserId", "44"}, {"accesseeTokenId", "444"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}, {"accesseeUserId", "44"}, {"accesseeTokenId", "444"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_016
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_016, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"accesserDeviceId", "acer11"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "44"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "444"},
        {"accesseeDeviceId", "acee22"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer22"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"accesserDeviceId", "acer2"}, {"accesserUserId", "33"}, {"accesserTokenId", "333"},
        {"accesseeDeviceId", "123456"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_022
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_022, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer22");
    accesser.SetAccesserUserId(33);
    accesser.SetAccesserAccountId("a22");
    accesser.SetAccesserTokenId(333);
    accesser.SetAccesserBundleName("b22");
    accesser.SetAccesserHapSignature("h22");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee22");
    accessee.SetAccesseeUserId(555);
    accessee.SetAccesseeAccountId("a2");
    accessee.SetAccesseeTokenId(444);
    accessee.SetAccesseeBundleName("bb2");
    accessee.SetAccesseeHapSignature("h2");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(99);
    profile.SetLastAuthTime(66);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_003
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_003, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer3");
    accesser.SetAccesserUserId(55);
    accesser.SetAccesserAccountId("a3");
    accesser.SetAccesserTokenId(555);
    accesser.SetAccesserBundleName("b3");
    accesser.SetAccesserHapSignature("h3");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee3");
    accessee.SetAccesseeUserId(66);
    accessee.SetAccesseeAccountId("a3");
    accessee.SetAccesseeTokenId(666);
    accessee.SetAccesseeBundleName("bb3");
    accessee.SetAccesseeHapSignature("h3");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("6666");
    profile.SetSessionKey("key1");
    profile.SetBindType(3);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(1);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_033
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_033, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer33");
    accesser.SetAccesserUserId(10086);
    accesser.SetAccesserAccountId("a33");
    accesser.SetAccesserTokenId(555);
    accesser.SetAccesserBundleName("b3");
    accesser.SetAccesserHapSignature("h33");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee33");
    accessee.SetAccesseeUserId(10010);
    accessee.SetAccesseeAccountId("a33");
    accessee.SetAccesseeTokenId(666);
    accessee.SetAccesseeBundleName("bb33");
    accessee.SetAccesseeHapSignature("h33");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("6666");
    profile.SetSessionKey("key1");
    profile.SetBindType(3);
    profile.SetAuthenticationType(33);
    profile.SetDeviceIdType(33);
    profile.SetDeviceIdHash("abcd33");
    profile.SetStatus(1);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_004
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_004, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer4");
    accesser.SetAccesserUserId(77);
    accesser.SetAccesserAccountId("a4");
    accesser.SetAccesserTokenId(777);
    accesser.SetAccesserBundleName("b4");
    accesser.SetAccesserHapSignature("h4");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee4");
    accessee.SetAccesseeUserId(88);
    accessee.SetAccesseeAccountId("a4");
    accessee.SetAccesseeTokenId(888);
    accessee.SetAccesseeBundleName("bb4");
    accessee.SetAccesseeHapSignature("h4");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("6666");
    profile.SetSessionKey("key1");
    profile.SetBindType(4);
    profile.SetAuthenticationType(99);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(66);
    profile.SetLastAuthTime(20);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_044
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_044, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer44");
    accesser.SetAccesserUserId(77);
    accesser.SetAccesserAccountId("a44");
    accesser.SetAccesserTokenId(777);
    accesser.SetAccesserBundleName("b4");
    accesser.SetAccesserHapSignature("h44");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee44");
    accessee.SetAccesseeUserId(88);
    accessee.SetAccesseeAccountId("a44");
    accessee.SetAccesseeTokenId(888);
    accessee.SetAccesseeBundleName("bb4");
    accessee.SetAccesseeHapSignature("h44");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("9999");
    profile.SetSessionKey("key1");
    profile.SetBindType(4);
    profile.SetAuthenticationType(100);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(66);
    profile.SetLastAuthTime(20);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: PutAccessControlProfile_005
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, PutAccessControlProfile_005, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId("acer44");
    accesser.SetAccesserUserId(77);
    accesser.SetAccesserAccountId("a44");
    accesser.SetAccesserTokenId(777);
    accesser.SetAccesserBundleName("b4");
    accesser.SetAccesserHapSignature("h44");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("acee4");
    accessee.SetAccesseeUserId(88);
    accessee.SetAccesseeAccountId("a4");
    accessee.SetAccesseeTokenId(888);
    accessee.SetAccesseeBundleName("bb4");
    accessee.SetAccesseeHapSignature("h4");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("9999");
    profile.SetSessionKey("key1");
    profile.SetBindType(4);
    profile.SetAuthenticationType(100);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(1);
    profile.SetValidPeriod(66);
    profile.SetLastAuthTime(20);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_001, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "22"}, {"bundleName", "bb1"}, {"bindType", "256"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        ValuesBucket value;
        ProfileUtils::AccessControlProfileToEntries(profile[i], value);
        AccessControlProfile aclProfile;
        ProfileUtils::EntriesToAccessControlProfile(value, aclProfile);
        value.Clear();
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        ProfileUtils::AccesserToEntries(profile[i], value);
        Accesser accesser;
        ProfileUtils::EntriesToAccesser(value, accesser);
        value.Clear();
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
        ProfileUtils::AccesseeToEntries(profile[i], value);
        Accessee accessee;
        ProfileUtils::EntriesToAccessee(value, accessee);
        value.Clear();
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "11"}, {"bundleName", "b1"}, {"bindType", "256"}, {"status", "0"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_002, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "555"}, {"bundleName", "b1"}, {"trustDeviceId", "123456"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "33"}, {"bundleName", "b1"}, {"trustDeviceId", "123456"}, {"status", "0"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_003
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_003, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"bundleName", "bb3"}, {"trustDeviceId", "6666"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"bundleName", "b3"}, {"trustDeviceId", "6666"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_004
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_004, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"bundleName", "bb4"}, {"bindType", "4"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_005
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_005, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "77"}, {"accountId", "a44"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "88"}, {"accountId", "a44"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "88"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "77"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_006
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_006, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"tokenId", "777"}, {"trustDeviceId", "acer44"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"tokenId", "888"}, {"trustDeviceId", "acee4"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_007
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_007, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "33"}, {"bundleName", "b22"}, {"trustDeviceId", "123456"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_008
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_008, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "77"}, {"bundleName", "b4"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);

    parms.clear();
    profile.clear();
    parms.insert({{"userId", "44"}, {"bundleName", "b4"}, {"trustDeviceId", "123456"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_009
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_009, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"bundleName", "b4"}, {"bindType", "4"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_010
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_010, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"bundleName", "888"}, {"bindType", "4"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"bundleName", "b4"}, {"bindType", "88"}, {"status", "8"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"bundleName", "888"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"bundleName", "b4"}, {"trustDeviceId", "88888"}, {"status", "0"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "88888"}, {"accountId", "a44"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "88888"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_011
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_011, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"tokenId", "55555"}, {"trustDeviceId", "11111"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"tokenId", "55555"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "001"}, {"bundleName", "b1"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "001"}, {"bundleName", "b1"}, {"trustDeviceId", "99999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "001"}, {"bundleName", "b1"}, {"bindType", "99999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    parms.insert({{"userId", "001"}, {"bundleName", "b1"}, {"bindType", "4"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAccessControlProfile_012
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAccessControlProfile_012, TestSize.Level1)
{
    string invalid;
    std::vector<ValueObject> val;
    for (int i = 0; i < 4100; ++i) {
        val.push_back(ValueObject(1));
        invalid += "1";
    }
    std::vector<AccessControlProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(invalid, "99999", 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile("b1", invalid, 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(invalid, 4, 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, invalid, 4, 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, invalid, "99999", 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, "b1", invalid, 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfileByTokenId(1, invalid, 1, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(1, invalid, profile);
    EXPECT_NE(ret, DP_SUCCESS);

    OHOS::DistributedDeviceProfile::TrustProfileManager::GetInstance().
        GetResultSet(invalid, std::vector<ValueObject> {});

    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetResultSet("111", val);
}

/*
 * @tc.name: UpdateAccessControlProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, UpdateAccessControlProfile_001, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserId(1);
    accesser.SetAccesserDeviceId("upacer1");
    accesser.SetAccesserUserId(101);
    accesser.SetAccesserAccountId("upa1");
    accesser.SetAccesserTokenId(1001);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("uph1");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeId(1);
    accessee.SetAccesseeDeviceId("upacee1");
    accessee.SetAccesseeUserId(22);
    accessee.SetAccesseeAccountId("upa1");
    accessee.SetAccesseeTokenId(2002);
    accessee.SetAccesseeBundleName("yyy");
    accessee.SetAccesseeHapSignature("uph1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetAccessControlId(1);
    profile.SetAccesserId(1);
    profile.SetAccesseeId(1);
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateTrustDeviceProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, UpdateTrustDeviceProfile_001, TestSize.Level1)
{
    TrustDeviceProfile profile;
    profile.SetDeviceId("56465456465");

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateTrustDeviceProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateAccessControlProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, UpdateAccessControlProfile_002, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserId(3);
    accesser.SetAccesserDeviceId("upacer2");
    accesser.SetAccesserUserId(555);
    accesser.SetAccesserAccountId("upa1");
    accesser.SetAccesserTokenId(4444);
    accesser.SetAccesserBundleName("b1");
    accesser.SetAccesserHapSignature("uph1");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeId(3);
    accessee.SetAccesseeDeviceId("upacee2");
    accessee.SetAccesseeUserId(456);
    accessee.SetAccesseeAccountId("upa2");
    accessee.SetAccesseeTokenId(5555);
    accessee.SetAccesseeBundleName("b1");
    accessee.SetAccesseeHapSignature("uph2");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetAccessControlId(3);
    profile.SetAccesserId(3);
    profile.SetAccesseeId(3);
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key2");
    profile.SetBindType(2);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("abcd");
    profile.SetStatus(0);
    profile.SetValidPeriod(999);
    profile.SetLastAuthTime(666);
    profile.SetBindLevel(0);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: UpdateAccessControlProfile_003
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, UpdateAccessControlProfile_003, TestSize.Level1)
{
    Accesser accesser;
    accesser.SetAccesserId(5);
    accesser.SetAccesserDeviceId("upacer3");
    accesser.SetAccesserUserId(55);
    accesser.SetAccesserAccountId("upa3");
    accesser.SetAccesserTokenId(555);
    accesser.SetAccesserBundleName("b3");
    accesser.SetAccesserHapSignature("uph3");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeId(5);
    accessee.SetAccesseeDeviceId("upacee3");
    accessee.SetAccesseeUserId(66);
    accessee.SetAccesseeAccountId("upa3");
    accessee.SetAccesseeTokenId(6666);
    accessee.SetAccesseeBundleName("bb3");
    accessee.SetAccesseeHapSignature("uph3");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetAccessControlId(5);
    profile.SetAccesserId(5);
    profile.SetAccesseeId(5);
    profile.SetTrustDeviceId("6666");
    profile.SetSessionKey("key1");
    profile.SetBindType(3);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("aaaa");
    profile.SetStatus(1);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);

    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(9);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_002, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(8);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_003
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_003, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(5);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_004
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_004, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(6);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_005
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_005, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(7);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAllAccessControlProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAllAccessControlProfile_001, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllAccessControlProfile(profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
        std::cout << profile[i].GetAccesser().dump() <<std::endl;
        std::cout << profile[i].GetAccessee().dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetAllTrustDeviceProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetAllTrustDeviceProfile_001, TestSize.Level1)
{
    std::vector<TrustDeviceProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllTrustDeviceProfile(profile);
    for (size_t i = 0; i < profile.size(); i++) {
        std::cout << profile[i].dump() <<std::endl;
    }
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetTrustDeviceProfile_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetTrustDeviceProfile_001, TestSize.Level1)
{
    TrustDeviceProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetTrustDeviceProfile("123456", profile);
    ValuesBucket value;
    ProfileUtils::TrustDeviceProfileToEntries(profile, value);
    std::cout << profile.dump() <<std::endl;
    ProfileUtils::EntriesToTrustDeviceProfile(value, profile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: GetTrustDeviceProfile_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, GetTrustDeviceProfile_002, TestSize.Level1)
{
    TrustDeviceProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetTrustDeviceProfile("8888", profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: DeleteAccessControlProfile_006
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, DeleteAccessControlProfile_006, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(10);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(4);
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(3);
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(2);
    EXPECT_EQ(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(1);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: RdbStoreIsNullptr_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, RdbStoreIsNullptr_001, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;
    
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UnInit();
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CreateTable();
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CreateUniqueIndex();
    EXPECT_NE(ret, DP_SUCCESS);

    TrustDeviceProfile profile;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetTrustDeviceProfile("8888", profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutTrustDeviceProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateTrustDeviceProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteTrustDeviceProfile("123");
    EXPECT_NE(ret, DP_SUCCESS);

    std::vector<TrustDeviceProfile> profiles;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllTrustDeviceProfile(profiles);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: RdbStoreIsNullptr_002
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, RdbStoreIsNullptr_002, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;

    AccessControlProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccessControlProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccessControlProfile(1);
    EXPECT_NE(ret, DP_SUCCESS);

    std::vector<AccessControlProfile> profiles;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllAccessControlProfile(profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccesserProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccesseeProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().SetAccessControlId(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().SetAccesserId(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().SetAccesseeId(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    profile.SetAccessControlId(1);
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccesserProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAccesseeProfile(profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: RdbStoreIsNullptr_003
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, RdbStoreIsNullptr_003, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;

    std::vector<AccessControlProfile> profiles;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "001"}, {"bundleName", "b1"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"userId", "11"}, {"bundleName", "b1"}, {"bindType", "1"}, {"status", "0"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"bundleName", "b4"}, {"bindType", "1"}, {"status", "0"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"tokenId", "55555"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"bundleName", "b4"}, {"trustDeviceId", "9999"}, {"status", "1"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"userId", "77"}, {"accountId", "a44"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    parms.clear();
    profiles.clear();
    parms.insert({{"userId", "77"}});
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfile(parms, profiles);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: RdbStoreIsNullptr_004
 * @tc.desc: Normal testCase of TrustProfileManagerTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, RdbStoreIsNullptr_004, TestSize.Level1)
{
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;

    AccessControlProfile profile;
    int32_t status = 0;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetResultStatus("123", status);
    EXPECT_NE(ret, DP_SUCCESS);

    std::vector<AccessControlProfile> profiles;
    std::shared_ptr<ResultSet> resultSet;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfiles(resultSet, 1, 1, 1, "1", profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfiles(resultSet, 1, 1, 1, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfilesByTokenId(resultSet, 1, 1, "1", 1, profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAccessControlProfilesByDeviceId(resultSet, 1, 1, "1", profiles);
    EXPECT_NE(ret, DP_SUCCESS);

    Accesser accesser;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccesserCheck(1, accesser);
    EXPECT_NE(ret, DP_SUCCESS);

    Accessee accessee;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteAccesseeCheck(1, accessee);
    EXPECT_NE(ret, DP_SUCCESS);

    AccessControlProfile oldProfile;
    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().UpdateAclCheck(profile, oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);

    ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().DeleteTrustDeviceCheck(profile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: Check_001
 * @tc.desc: Normal testCase of TrustProfileManagerTest for Check
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTest, Check_001, TestSize.Level1)
{
    AccessControlProfile profile;
    profile.SetAccessControlId(1);
    profile.SetAccesserId(1);
    profile.SetAccesseeId(1);
    profile.SetTrustDeviceId("123456");
    profile.GetAccessee().SetAccesseeUserId(6666);
    profile.SetStatus(0);
    bool ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckUserIdExists(1, 1, "123", 100, "456", 101);
    EXPECT_EQ(ret, false);

    AccessControlProfile oldProfile;
    oldProfile.SetStatus(1);
    profile.SetTrustDeviceId("123456");
    int32_t result = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().NotifyCheck(profile, oldProfile);
    EXPECT_NE(result, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
