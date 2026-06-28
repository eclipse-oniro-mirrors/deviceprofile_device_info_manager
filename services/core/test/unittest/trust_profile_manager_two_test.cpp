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
    const std::string TAG = "TrustProfileManagerTwoTest";
}

static int64_t GetAclIdByDeviceId(const std::string& deviceId)
{
    std::vector<AccessControlProfile> profiles;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().GetAllAccessControlProfile(profiles);
    if (ret != DP_SUCCESS) {
        return -1;
    }
    for (auto& p : profiles) {
        if (p.GetTrustDeviceId() == deviceId) {
            return p.GetAccessControlId();
        }
    }
    return -1;
}

class TrustProfileManagerTwoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TrustProfileManagerTwoTest::SetUpTestCase()
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        TrustProfileManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

void TrustProfileManagerTwoTest::TearDownTestCase()
{
    OHOS::DistributedDeviceProfile::
        TrustProfileManager::GetInstance().UnInit();
}

void TrustProfileManagerTwoTest::SetUp()
{
}

void TrustProfileManagerTwoTest::TearDown()
{
}

/*
 * @tc.name: ParseServiceIdFromJson_001
 * @tc.desc: ParseServiceIdFromJson with empty string
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, ParseServiceIdFromJson_001, TestSize.Level1)
{
    int32_t serviceId = -1;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().ParseServiceIdFromJson("", serviceId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    EXPECT_EQ(serviceId, -1);
}

/*
 * @tc.name: ParseServiceIdFromJson_002
 * @tc.desc: ParseServiceIdFromJson with invalid JSON
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, ParseServiceIdFromJson_002, TestSize.Level1)
{
    int32_t serviceId = -1;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().ParseServiceIdFromJson("{invalid}", serviceId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    EXPECT_EQ(serviceId, -1);
}

/*
 * @tc.name: ParseServiceIdFromJson_003
 * @tc.desc: ParseServiceIdFromJson with missing serviceId field
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, ParseServiceIdFromJson_003, TestSize.Level1)
{
    int32_t serviceId = -1;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().ParseServiceIdFromJson("{\"other\": 123}", serviceId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    EXPECT_EQ(serviceId, -1);
}

/*
 * @tc.name: ParseServiceIdFromJson_004
 * @tc.desc: ParseServiceIdFromJson with non-number serviceId
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, ParseServiceIdFromJson_004, TestSize.Level1)
{
    int32_t serviceId = -1;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().ParseServiceIdFromJson("{\"serviceId\": \"abc\"}", serviceId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    EXPECT_EQ(serviceId, -1);
}

/*
 * @tc.name: ParseServiceIdFromJson_005
 * @tc.desc: ParseServiceIdFromJson with valid serviceId
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, ParseServiceIdFromJson_005, TestSize.Level1)
{
    int32_t serviceId = -1;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().ParseServiceIdFromJson("{\"serviceId\": 42}", serviceId);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(serviceId, 42);
}

/*
 * @tc.name: CheckAccountAclExists_001
 * @tc.desc: CheckAccountAclExists with rdbStore_ null
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_001, TestSize.Level1)
{
    AccessControlProfile profile;
    bool isExists = true;
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclExists(profile, isExists);
    EXPECT_NE(ret, DP_SUCCESS);
    OHOS::DistributedDeviceProfile::TrustProfileManager::GetInstance().Init();
}

/*
 * @tc.name: CheckAccountAclExists_002
 * @tc.desc: CheckAccountAclExists no matching record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_002, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_other");
    storedAccesser.SetAccesserUserId(999);
    storedAccesser.SetAccesserAccountId("acc_other");
    storedAccesser.SetAccesserTokenId(9999);
    storedAccesser.SetAccesserBundleName("b_other");
    storedAccesser.SetAccesserHapSignature("h_other");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_other");
    storedAccessee.SetAccesseeUserId(888);
    storedAccessee.SetAccesseeAccountId("acc_other");
    storedAccessee.SetAccesseeTokenId(8888);
    storedAccessee.SetAccesseeBundleName("bb_other");
    storedAccessee.SetAccesseeHapSignature("h_other");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_other");
    storedProfile.SetSessionKey("k_other");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_other");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_other");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("acer_no_match");
    queryAccesser.SetAccesserUserId(11);
    queryAccesser.SetAccesserAccountId("acc_no_match");
    queryAccesser.SetAccesserTokenId(111);
    queryAccesser.SetAccesserBundleName("b1");
    queryAccesser.SetAccesserHapSignature("h1");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("dev_no_match");
    queryAccessee.SetAccesseeUserId(22);
    queryAccessee.SetAccesseeAccountId("acc_no_match");
    queryAccessee.SetAccesseeTokenId(222);
    queryAccessee.SetAccesseeBundleName("bb1");
    queryAccessee.SetAccesseeHapSignature("h1");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_no_match");
    queryProfile.SetSessionKey("k1");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh1");
    queryProfile.SetStatus(0);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    bool isExists = true;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, false);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclExists_003
 * @tc.desc: CheckAccountAclExists with matching forward record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_003, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_fwd");
    storedAccesser.SetAccesserUserId(111);
    storedAccesser.SetAccesserAccountId("acc_fwd");
    storedAccesser.SetAccesserTokenId(1111);
    storedAccesser.SetAccesserBundleName("bf1");
    storedAccesser.SetAccesserHapSignature("hf1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_fwd");
    storedAccessee.SetAccesseeUserId(222);
    storedAccessee.SetAccesseeAccountId("acc_fwd");
    storedAccessee.SetAccesseeTokenId(2222);
    storedAccessee.SetAccesseeBundleName("bbf1");
    storedAccessee.SetAccesseeHapSignature("hf1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("extra");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_fwd");
    storedProfile.SetSessionKey("kf1");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_fwd");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_fwd");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("acer_fwd");
    queryAccesser.SetAccesserUserId(111);
    queryAccesser.SetAccesserAccountId("acc_fwd");
    queryAccesser.SetAccesserTokenId(1111);
    queryAccesser.SetAccesserBundleName("bf1");
    queryAccesser.SetAccesserHapSignature("hf1");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("dev_fwd");
    queryAccessee.SetAccesseeUserId(222);
    queryAccessee.SetAccesseeAccountId("acc_fwd");
    queryAccessee.SetAccesseeTokenId(2222);
    queryAccessee.SetAccesseeBundleName("bbf1");
    queryAccessee.SetAccesseeHapSignature("hf1");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_fwd");
    queryProfile.SetSessionKey("kf1");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh_fwd");
    queryProfile.SetStatus(1);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    bool isExists = false;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, true);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclExists_004
 * @tc.desc: CheckAccountAclExists with swapped deviceId (accesseeDeviceId == trustDeviceId)
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_004, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_swap");
    storedAccesser.SetAccesserUserId(333);
    storedAccesser.SetAccesserAccountId("acc_swap");
    storedAccesser.SetAccesserTokenId(3333);
    storedAccesser.SetAccesserBundleName("bs1");
    storedAccesser.SetAccesserHapSignature("hs1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_swap");
    storedAccessee.SetAccesseeUserId(444);
    storedAccessee.SetAccesseeAccountId("acc_swap");
    storedAccessee.SetAccesseeTokenId(4444);
    storedAccessee.SetAccesseeBundleName("bbs1");
    storedAccessee.SetAccesseeHapSignature("hs1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_swap");
    storedProfile.SetSessionKey("ks1");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_swap");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_swap");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("dev_swap");
    queryAccesser.SetAccesserUserId(444);
    queryAccesser.SetAccesserAccountId("acc_swap");
    queryAccesser.SetAccesserTokenId(4444);
    queryAccesser.SetAccesserBundleName("bbs1");
    queryAccesser.SetAccesserHapSignature("hs1");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("acer_swap");
    queryAccessee.SetAccesseeUserId(333);
    queryAccessee.SetAccesseeAccountId("acc_swap");
    queryAccessee.SetAccesseeTokenId(3333);
    queryAccessee.SetAccesseeBundleName("bs1");
    queryAccessee.SetAccesseeHapSignature("hs1");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_swap");
    queryProfile.SetSessionKey("ks1");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh_swap");
    queryProfile.SetStatus(1);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    bool isExists = false;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, true);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclActiveCount_001
 * @tc.desc: CheckAccountAclActiveCount with rdbStore_ null
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclActiveCount_001, TestSize.Level1)
{
    AccessControlProfile profile;
    int32_t resultCount = -1;
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclActiveCount(profile, resultCount);
    EXPECT_NE(ret, DP_SUCCESS);
    OHOS::DistributedDeviceProfile::TrustProfileManager::GetInstance().Init();
}

/*
 * @tc.name: CheckAccountAclActiveCount_002
 * @tc.desc: CheckAccountAclActiveCount no matching active record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclActiveCount_002, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_cnt_other");
    storedAccesser.SetAccesserUserId(555);
    storedAccesser.SetAccesserAccountId("acc_cnt_other");
    storedAccesser.SetAccesserTokenId(5555);
    storedAccesser.SetAccesserBundleName("bc1");
    storedAccesser.SetAccesserHapSignature("hc1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_cnt_other");
    storedAccessee.SetAccesseeUserId(666);
    storedAccessee.SetAccesseeAccountId("acc_cnt_other");
    storedAccessee.SetAccesseeTokenId(6666);
    storedAccessee.SetAccesseeBundleName("bbc1");
    storedAccessee.SetAccesseeHapSignature("hc1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_cnt_other");
    storedProfile.SetSessionKey("kc_other");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_cnt_other");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_cnt_other");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("acer_cnt1");
    queryAccesser.SetAccesserUserId(555);
    queryAccesser.SetAccesserAccountId("acc_cnt1");
    queryAccesser.SetAccesserTokenId(5555);
    queryAccesser.SetAccesserBundleName("bc1");
    queryAccesser.SetAccesserHapSignature("hc1");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("dev_cnt1");
    queryAccessee.SetAccesseeUserId(666);
    queryAccessee.SetAccesseeAccountId("acc_cnt1");
    queryAccessee.SetAccesseeTokenId(6666);
    queryAccessee.SetAccesseeBundleName("bbc1");
    queryAccessee.SetAccesseeHapSignature("hc1");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_cnt1");
    queryProfile.SetSessionKey("kc1");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh_cnt1");
    queryProfile.SetStatus(0);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    int32_t resultCount = 0;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclActiveCount(queryProfile, resultCount);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(resultCount, 0);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclActiveCount_003
 * @tc.desc: CheckAccountAclActiveCount with matching active record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclActiveCount_003, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_act");
    storedAccesser.SetAccesserUserId(777);
    storedAccesser.SetAccesserAccountId("acc_act");
    storedAccesser.SetAccesserTokenId(7777);
    storedAccesser.SetAccesserBundleName("ba1");
    storedAccesser.SetAccesserHapSignature("ha1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_act");
    storedAccessee.SetAccesseeUserId(888);
    storedAccessee.SetAccesseeAccountId("acc_act");
    storedAccessee.SetAccesseeTokenId(8888);
    storedAccessee.SetAccesseeBundleName("bba1");
    storedAccessee.SetAccesseeHapSignature("ha1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_act");
    storedProfile.SetSessionKey("ka1");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_act");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_act");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("acer_act");
    queryAccesser.SetAccesserUserId(777);
    queryAccesser.SetAccesserAccountId("acc_act");
    queryAccesser.SetAccesserTokenId(7777);
    queryAccesser.SetAccesserBundleName("ba1");
    queryAccesser.SetAccesserHapSignature("ha1");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("dev_act");
    queryAccessee.SetAccesseeUserId(888);
    queryAccessee.SetAccesseeAccountId("acc_act");
    queryAccessee.SetAccesseeTokenId(8888);
    queryAccessee.SetAccesseeBundleName("bba1");
    queryAccessee.SetAccesseeHapSignature("ha1");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_act");
    queryProfile.SetSessionKey("ka1");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh_act");
    queryProfile.SetStatus(1);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    int32_t resultCount = 0;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().CheckAccountAclActiveCount(queryProfile, resultCount);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(resultCount, 1);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: NotifyAccountAclCheck_001
 * @tc.desc: NotifyAccountAclCheck with rdbStore_ null
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, NotifyAccountAclCheck_001, TestSize.Level1)
{
    AccessControlProfile profile;
    AccessControlProfile oldProfile;
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().NotifyAccountAclCheck(profile, oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    OHOS::DistributedDeviceProfile::TrustProfileManager::GetInstance().Init();
}

/*
 * @tc.name: NotifyAccountAclCheck_002
 * @tc.desc: NotifyAccountAclCheck conditions not met (no active count)
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, NotifyAccountAclCheck_002, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_n_other");
    storedAccesser.SetAccesserUserId(999);
    storedAccesser.SetAccesserAccountId("acc_n_other");
    storedAccesser.SetAccesserTokenId(9999);
    storedAccesser.SetAccesserBundleName("bn1");
    storedAccesser.SetAccesserHapSignature("hn1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_n_other");
    storedAccessee.SetAccesseeUserId(1010);
    storedAccessee.SetAccesseeAccountId("acc_n_other");
    storedAccessee.SetAccesseeTokenId(10101);
    storedAccessee.SetAccesseeBundleName("bbn1");
    storedAccessee.SetAccesseeHapSignature("hn1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_n_other");
    storedProfile.SetSessionKey("kn_other");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_n_other");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_n_other");

    Accesser accesser;
    accesser.SetAccesserDeviceId("acer_notify");
    accesser.SetAccesserUserId(1111);
    accesser.SetAccesserAccountId("acc_notify");
    accesser.SetAccesserTokenId(11111);
    accesser.SetAccesserBundleName("bn1");
    accesser.SetAccesserHapSignature("hn1");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("dev_notify");
    accessee.SetAccesseeUserId(2222);
    accessee.SetAccesseeAccountId("acc_notify");
    accessee.SetAccesseeTokenId(22222);
    accessee.SetAccesseeBundleName("bbn1");
    accessee.SetAccesseeHapSignature("hn1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("dev_notify");
    profile.SetSessionKey("kn1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("hsh_notify");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    AccessControlProfile oldProfile;
    oldProfile.SetStatus(1);

    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().NotifyAccountAclCheck(profile, oldProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: QueryServiceIdList_001
 * @tc.desc: QueryServiceIdList with rdbStore_ null
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, QueryServiceIdList_001, TestSize.Level1)
{
    AccessControlProfile profile;
    std::vector<int32_t> serviceIdList;
    OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().rdbStore_ = nullptr;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().QueryServiceIdList(profile, serviceIdList);
    EXPECT_NE(ret, DP_SUCCESS);
    OHOS::DistributedDeviceProfile::TrustProfileManager::GetInstance().Init();
}

/*
 * @tc.name: QueryServiceIdList_002
 * @tc.desc: QueryServiceIdList no matching record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, QueryServiceIdList_002, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_q_other");
    storedAccesser.SetAccesserUserId(1111);
    storedAccesser.SetAccesserAccountId("acc_q_other");
    storedAccesser.SetAccesserTokenId(11111);
    storedAccesser.SetAccesserBundleName("bq1");
    storedAccesser.SetAccesserHapSignature("hq1");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_q_other");
    storedAccessee.SetAccesseeUserId(2222);
    storedAccessee.SetAccesseeAccountId("acc_q_other");
    storedAccessee.SetAccesseeTokenId(22222);
    storedAccessee.SetAccesseeBundleName("bbq1");
    storedAccessee.SetAccesseeHapSignature("hq1");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("x");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_q_other");
    storedProfile.SetSessionKey("kq_other");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_q_other");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_q_other");

    Accesser accesser;
    accesser.SetAccesserDeviceId("acer_qry");
    accesser.SetAccesserUserId(3333);
    accesser.SetAccesserAccountId("acc_qry");
    accesser.SetAccesserTokenId(33333);
    accesser.SetAccesserBundleName("bq1");
    accesser.SetAccesserHapSignature("hq1");
    accesser.SetAccesserBindLevel(1);

    Accessee accessee;
    accessee.SetAccesseeDeviceId("dev_qry");
    accessee.SetAccesseeUserId(4444);
    accessee.SetAccesseeAccountId("acc_qry");
    accessee.SetAccesseeTokenId(44444);
    accessee.SetAccesseeBundleName("bbq1");
    accessee.SetAccesseeHapSignature("hq1");
    accessee.SetAccesseeBindLevel(1);

    AccessControlProfile profile;
    profile.SetTrustDeviceId("dev_qry");
    profile.SetSessionKey("kq1");
    profile.SetBindType(256);
    profile.SetAuthenticationType(1);
    profile.SetDeviceIdType(1);
    profile.SetDeviceIdHash("hsh_qry");
    profile.SetStatus(0);
    profile.SetValidPeriod(1);
    profile.SetLastAuthTime(5);
    profile.SetBindLevel(1);
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);

    std::vector<int32_t> serviceIdList;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().QueryServiceIdList(profile, serviceIdList);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(serviceIdList.size(), 0);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: QueryServiceIdList_003
 * @tc.desc: QueryServiceIdList with matching record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, QueryServiceIdList_003, TestSize.Level1)
{
    Accesser storedAccesser;
    storedAccesser.SetAccesserDeviceId("acer_qry2");
    storedAccesser.SetAccesserUserId(3333);
    storedAccesser.SetAccesserAccountId("acc_qry2");
    storedAccesser.SetAccesserTokenId(33333);
    storedAccesser.SetAccesserBundleName("bq2");
    storedAccesser.SetAccesserHapSignature("hq2");
    storedAccesser.SetAccesserBindLevel(1);

    Accessee storedAccessee;
    storedAccessee.SetAccesseeDeviceId("dev_qry2");
    storedAccessee.SetAccesseeUserId(4444);
    storedAccessee.SetAccesseeAccountId("acc_qry2");
    storedAccessee.SetAccesseeTokenId(44444);
    storedAccessee.SetAccesseeBundleName("bbq2");
    storedAccessee.SetAccesseeHapSignature("hq2");
    storedAccessee.SetAccesseeBindLevel(1);
    storedAccessee.SetAccesseeExtraData("{\"serviceId\": 100}");

    AccessControlProfile storedProfile;
    storedProfile.SetTrustDeviceId("dev_qry2");
    storedProfile.SetSessionKey("kq2");
    storedProfile.SetBindType(256);
    storedProfile.SetAuthenticationType(1);
    storedProfile.SetDeviceIdType(1);
    storedProfile.SetDeviceIdHash("hsh_qry2");
    storedProfile.SetStatus(1);
    storedProfile.SetValidPeriod(1);
    storedProfile.SetLastAuthTime(5);
    storedProfile.SetBindLevel(1);
    storedProfile.SetAccesser(storedAccesser);
    storedProfile.SetAccessee(storedAccessee);

    int32_t putRet = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_qry2");

    Accesser queryAccesser;
    queryAccesser.SetAccesserDeviceId("acer_qry2");
    queryAccesser.SetAccesserUserId(3333);
    queryAccesser.SetAccesserAccountId("acc_qry2");
    queryAccesser.SetAccesserTokenId(33333);
    queryAccesser.SetAccesserBundleName("bq2");
    queryAccesser.SetAccesserHapSignature("hq2");
    queryAccesser.SetAccesserBindLevel(1);

    Accessee queryAccessee;
    queryAccessee.SetAccesseeDeviceId("dev_qry2");
    queryAccessee.SetAccesseeUserId(4444);
    queryAccessee.SetAccesseeAccountId("acc_qry2");
    queryAccessee.SetAccesseeTokenId(44444);
    queryAccessee.SetAccesseeBundleName("bbq2");
    queryAccessee.SetAccesseeHapSignature("hq2");
    queryAccessee.SetAccesseeBindLevel(1);

    AccessControlProfile queryProfile;
    queryProfile.SetTrustDeviceId("dev_qry2");
    queryProfile.SetSessionKey("kq2");
    queryProfile.SetBindType(256);
    queryProfile.SetAuthenticationType(1);
    queryProfile.SetDeviceIdType(1);
    queryProfile.SetDeviceIdHash("hsh_qry2");
    queryProfile.SetStatus(1);
    queryProfile.SetValidPeriod(1);
    queryProfile.SetLastAuthTime(5);
    queryProfile.SetBindLevel(1);
    queryProfile.SetAccesser(queryAccesser);
    queryProfile.SetAccessee(queryAccessee);

    std::vector<int32_t> serviceIdList;
    int32_t ret = OHOS::DistributedDeviceProfile::TrustProfileManager::
        GetInstance().QueryServiceIdList(queryProfile, serviceIdList);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(serviceIdList.size(), 1);
    EXPECT_EQ(serviceIdList[0], 100);

    if (storedAclId != -1) {
        OHOS::DistributedDeviceProfile::TrustProfileManager::
            GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
