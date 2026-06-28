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
    constexpr int32_t DEFAULT_VALID_PERIOD = 1;
    constexpr int32_t DEFAULT_LAST_AUTH_TIME = 5;
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

static Accesser MakeAccesser(const std::string& deviceId, int32_t userId,
    const std::string& accountId, int32_t tokenId)
{
    Accesser accesser;
    accesser.SetAccesserDeviceId(deviceId);
    accesser.SetAccesserUserId(userId);
    accesser.SetAccesserAccountId(accountId);
    accesser.SetAccesserTokenId(tokenId);
    accesser.SetAccesserBundleName("bundle_" + deviceId);
    accesser.SetAccesserHapSignature("sig_" + deviceId);
    accesser.SetAccesserBindLevel(static_cast<uint32_t>(BindLevel::USER));
    return accesser;
}

static Accessee MakeAccessee(const std::string& deviceId, int32_t userId,
    const std::string& accountId, int32_t tokenId,
    const std::string& extraData = "")
{
    Accessee accessee;
    accessee.SetAccesseeDeviceId(deviceId);
    accessee.SetAccesseeUserId(userId);
    accessee.SetAccesseeAccountId(accountId);
    accessee.SetAccesseeTokenId(tokenId);
    accessee.SetAccesseeBundleName("bundle_" + deviceId);
    accessee.SetAccesseeHapSignature("sig_" + deviceId);
    accessee.SetAccesseeBindLevel(static_cast<uint32_t>(BindLevel::USER));
    accessee.SetAccesseeExtraData(extraData);
    return accessee;
}

static AccessControlProfile MakeProfile(const std::string& trustDeviceId,
    const std::string& sessionKey, int32_t status,
    const Accesser& accesser, const Accessee& accessee)
{
    AccessControlProfile profile;
    profile.SetTrustDeviceId(trustDeviceId);
    profile.SetSessionKey(sessionKey);
    profile.SetBindType(static_cast<uint32_t>(BindType::POINT_TO_POINT));
    profile.SetAuthenticationType(static_cast<int32_t>(AuthenticationType::TEMPORARY));
    profile.SetDeviceIdType(static_cast<uint32_t>(DeviceIdType::UDID));
    profile.SetDeviceIdHash("hsh_" + trustDeviceId);
    profile.SetStatus(status);
    profile.SetValidPeriod(DEFAULT_VALID_PERIOD);
    profile.SetLastAuthTime(DEFAULT_LAST_AUTH_TIME);
    profile.SetBindLevel(static_cast<uint32_t>(BindLevel::USER));
    profile.SetAccesser(accesser);
    profile.SetAccessee(accessee);
    return profile;
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
    Accesser storedAccesser = MakeAccesser("acer_other", 999, "acc_other", 9999);
    Accessee storedAccessee = MakeAccessee("dev_other", 888, "acc_other", 8888, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_other", "k_other",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_other");

    Accesser queryAccesser = MakeAccesser("acer_no_match", 11, "acc_no_match", 111);
    Accessee queryAccessee = MakeAccessee("dev_no_match", 22, "acc_no_match", 222);
    AccessControlProfile queryProfile = MakeProfile("dev_no_match", "k1",
        static_cast<int32_t>(Status::INACTIVE), queryAccesser, queryAccessee);

    bool isExists = true;
    int32_t ret = TrustProfileManager::GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, false);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclExists_003
 * @tc.desc: CheckAccountAclExists with matching forward record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_003, TestSize.Level1)
{
    Accesser storedAccesser = MakeAccesser("acer_fwd", 111, "acc_fwd", 1111);
    Accessee storedAccessee = MakeAccessee("dev_fwd", 222, "acc_fwd", 2222, "extra");
    AccessControlProfile storedProfile = MakeProfile("dev_fwd", "kf1",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_fwd");

    Accesser queryAccesser = MakeAccesser("acer_fwd", 111, "acc_fwd", 1111);
    Accessee queryAccessee = MakeAccessee("dev_fwd", 222, "acc_fwd", 2222);
    AccessControlProfile queryProfile = MakeProfile("dev_fwd", "kf1",
        static_cast<int32_t>(Status::ACTIVE), queryAccesser, queryAccessee);

    bool isExists = false;
    int32_t ret = TrustProfileManager::GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, true);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclExists_004
 * @tc.desc: CheckAccountAclExists with swapped deviceId (accesseeDeviceId == trustDeviceId)
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclExists_004, TestSize.Level1)
{
    Accesser storedAccesser = MakeAccesser("acer_swap", 333, "acc_swap", 3333);
    Accessee storedAccessee = MakeAccessee("dev_swap", 444, "acc_swap", 4444, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_swap", "ks1",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_swap");

    Accesser queryAccesser = MakeAccesser("dev_swap", 444, "acc_swap", 4444);
    Accessee queryAccessee = MakeAccessee("acer_swap", 333, "acc_swap", 3333);
    AccessControlProfile queryProfile = MakeProfile("dev_swap", "ks1",
        static_cast<int32_t>(Status::ACTIVE), queryAccesser, queryAccessee);

    bool isExists = false;
    int32_t ret = TrustProfileManager::GetInstance().CheckAccountAclExists(queryProfile, isExists);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(isExists, true);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
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
    Accesser storedAccesser = MakeAccesser("acer_cnt_other", 555, "acc_cnt_other", 5555);
    Accessee storedAccessee = MakeAccessee("dev_cnt_other", 666, "acc_cnt_other", 6666, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_cnt_other", "kc_other",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_cnt_other");

    Accesser queryAccesser = MakeAccesser("acer_cnt1", 555, "acc_cnt1", 5555);
    Accessee queryAccessee = MakeAccessee("dev_cnt1", 666, "acc_cnt1", 6666);
    AccessControlProfile queryProfile = MakeProfile("dev_cnt1", "kc1",
        static_cast<int32_t>(Status::INACTIVE), queryAccesser, queryAccessee);

    int32_t resultCount = 0;
    int32_t ret = TrustProfileManager::GetInstance().CheckAccountAclActiveCount(queryProfile, resultCount);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(resultCount, 0);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: CheckAccountAclActiveCount_003
 * @tc.desc: CheckAccountAclActiveCount with matching active record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, CheckAccountAclActiveCount_003, TestSize.Level1)
{
    Accesser storedAccesser = MakeAccesser("acer_act", 777, "acc_act", 7777);
    Accessee storedAccessee = MakeAccessee("dev_act", 888, "acc_act", 8888, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_act", "ka1",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_act");

    Accesser queryAccesser = MakeAccesser("acer_act", 777, "acc_act", 7777);
    Accessee queryAccessee = MakeAccessee("dev_act", 888, "acc_act", 8888);
    AccessControlProfile queryProfile = MakeProfile("dev_act", "ka1",
        static_cast<int32_t>(Status::ACTIVE), queryAccesser, queryAccessee);

    int32_t resultCount = 0;
    int32_t ret = TrustProfileManager::GetInstance().CheckAccountAclActiveCount(queryProfile, resultCount);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(resultCount, 1);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
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
    Accesser storedAccesser = MakeAccesser("acer_n_other", 999, "acc_n_other", 9999);
    Accessee storedAccessee = MakeAccessee("dev_n_other", 1010, "acc_n_other", 10101, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_n_other", "kn_other",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_n_other");

    Accesser accesser = MakeAccesser("acer_notify", 1111, "acc_notify", 11111);
    Accessee accessee = MakeAccessee("dev_notify", 2222, "acc_notify", 22222);
    AccessControlProfile profile = MakeProfile("dev_notify", "kn1",
        static_cast<int32_t>(Status::INACTIVE), accesser, accessee);

    AccessControlProfile oldProfile;
    oldProfile.SetStatus(static_cast<int32_t>(Status::ACTIVE));

    int32_t ret = TrustProfileManager::GetInstance().NotifyAccountAclCheck(profile, oldProfile);
    EXPECT_EQ(ret, DP_SUCCESS);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
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
    Accesser storedAccesser = MakeAccesser("acer_q_other", 1111, "acc_q_other", 11111);
    Accessee storedAccessee = MakeAccessee("dev_q_other", 2222, "acc_q_other", 22222, "x");
    AccessControlProfile storedProfile = MakeProfile("dev_q_other", "kq_other",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_q_other");

    Accesser accesser = MakeAccesser("acer_qry", 3333, "acc_qry", 33333);
    Accessee accessee = MakeAccessee("dev_qry", 4444, "acc_qry", 44444);
    AccessControlProfile profile = MakeProfile("dev_qry", "kq1",
        static_cast<int32_t>(Status::INACTIVE), accesser, accessee);

    std::vector<int32_t> serviceIdList;
    int32_t ret = TrustProfileManager::GetInstance().QueryServiceIdList(profile, serviceIdList);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(serviceIdList.size(), 0);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}

/*
 * @tc.name: QueryServiceIdList_003
 * @tc.desc: QueryServiceIdList with matching record
 * @tc.type: FUNC
 */
HWTEST_F(TrustProfileManagerTwoTest, QueryServiceIdList_003, TestSize.Level1)
{
    Accesser storedAccesser = MakeAccesser("acer_qry2", 3333, "acc_qry2", 33333);
    Accessee storedAccessee = MakeAccessee("dev_qry2", 4444, "acc_qry2", 44444,
        "{\"serviceId\": 100}");
    AccessControlProfile storedProfile = MakeProfile("dev_qry2", "kq2",
        static_cast<int32_t>(Status::ACTIVE), storedAccesser, storedAccessee);

    int32_t putRet = TrustProfileManager::GetInstance().PutAccessControlProfile(storedProfile);
    EXPECT_EQ(putRet, DP_SUCCESS);
    int64_t storedAclId = GetAclIdByDeviceId("dev_qry2");

    Accesser queryAccesser = MakeAccesser("acer_qry2", 3333, "acc_qry2", 33333);
    Accessee queryAccessee = MakeAccessee("dev_qry2", 4444, "acc_qry2", 44444);
    AccessControlProfile queryProfile = MakeProfile("dev_qry2", "kq2",
        static_cast<int32_t>(Status::ACTIVE), queryAccesser, queryAccessee);

    std::vector<int32_t> serviceIdList;
    int32_t ret = TrustProfileManager::GetInstance().QueryServiceIdList(queryProfile, serviceIdList);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_EQ(serviceIdList.size(), 1);
    EXPECT_EQ(serviceIdList[0], 100);

    if (storedAclId != -1) {
        TrustProfileManager::GetInstance().DeleteAccessControlProfile(storedAclId);
    }
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
