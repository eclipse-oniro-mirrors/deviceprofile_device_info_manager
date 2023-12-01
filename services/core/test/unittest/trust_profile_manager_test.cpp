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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#include "profile_utils.h"
#include "trust_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "rdb_open_callback.h"


using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedDeviceProfile;
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
        GetInstance().PutAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_SUCCESS);
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

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
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
    accessee.SetAccesseeDeviceId("acee2");
    accessee.SetAccesseeUserId(44);
    accessee.SetAccesseeAccountId("a2");
    accessee.SetAccesseeTokenId(444);
    accessee.SetAccesseeBundleName("bb2");
    accessee.SetAccesseeHapSignature("h2");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("123456");
    profile.SetSessionKey("key1");
    profile.SetBindType(1);
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
    profile.SetBindType(1);
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
    parms.insert({{"userId", "22"}, {"bundleName", "bb1"}, {"bindType", "1"}, {"status", "0"}});
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
    parms.insert({{"accesserTokenId", "777"}, {"accesseeDeviceId", "acee4"}});
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

