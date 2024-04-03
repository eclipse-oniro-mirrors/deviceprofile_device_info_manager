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

#include "profile_utils.h"
#include "trust_profile_manager.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "rdb_open_callback.h"
#include "distributed_device_profile_client.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace std;
namespace {
    const std::string TAG = "DistributedDeviceProfileClientRdbTest";
    const uint32_t TEST_SA_ID = 4801;
}
class DistributedDeviceProfileClientRdbTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int ResultSize(std::shared_ptr<ResultSet>& resultSet);

    class SubscribeDPChangeListener : public ProfileChangeListenerStub {
    public:
        SubscribeDPChangeListener()
        {
            cout << "SubscribeDPChangeListener constructor" << endl;
        }
        ~SubscribeDPChangeListener()
        {
            cout << "SubscribeDPChangeListener destructor" << endl;
        }
        int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileAdd" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile)
        {
            cout << "OnTrustDeviceProfileDelete" << profile.dump() <<endl;
            return 0;
        }
        int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile, const TrustDeviceProfile& newProfile)
        {
            cout << "OnTrustDeviceProfileUpdate: oldProfile " << oldProfile.dump() <<endl;
            cout << "OnTrustDeviceProfileUpdate: newProfile " << newProfile.dump() <<endl;
            return 0;
        }
        int32_t OnDeviceProfileAdd(const DeviceProfile& profile)
        {
            return 0;
        }
        int32_t OnDeviceProfileDelete(const DeviceProfile& profile)
        {
            return 0;
        }
        int32_t OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile)
        {
            return 0;
        }
        int32_t OnServiceProfileAdd(const ServiceProfile& profile)
        {
            return 0;
        }
        int32_t OnServiceProfileDelete(const ServiceProfile& profile)
        {
            return 0;
        }
        int32_t OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileAdd(const CharacteristicProfile& profile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileDelete(const CharacteristicProfile& profile)
        {
            return 0;
        }
        int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
            const CharacteristicProfile& newProfile)
        {
            return 0;
        }
    };
};

void DistributedDeviceProfileClientRdbTest::SetUpTestCase()
{
    uint32_t saId = TEST_SA_ID;
    std::string subscribekey = "trust_device_profile";
    std::unordered_set<ProfileChangeType> subscribeTypes = {ProfileChangeType::TRUST_DEVICE_PROFILE_ADD,
        ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE, ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE};
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener = new(std::nothrow) SubscribeDPChangeListener;
    SubscribeInfo subscribeInfo(saId, subscribekey, subscribeTypes, subscribeDPChangeListener);
    DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscribeInfo);
}

void DistributedDeviceProfileClientRdbTest::TearDownTestCase()
{
}

void DistributedDeviceProfileClientRdbTest::SetUp()
{
}

void DistributedDeviceProfileClientRdbTest::TearDown()
{
}

int DistributedDeviceProfileClientRdbTest::ResultSize(std::shared_ptr<ResultSet> &resultSet)
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
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, PutAccessControlProfile_001, TestSize.Level1)
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
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().PutAccessControlProfile(profile);
    ValuesBucket value;
    ProfileUtils::AccessControlProfileToEntries(profile, value);
    ProfileUtils::EntriesToAccessControlProfile(value, profile);
    value.Clear();
    ProfileUtils::AccesserToEntries(profile, value);
    ProfileUtils::EntriesToAccesser(value, accesser);
    value.Clear();
    ProfileUtils::AccesseeToEntries(profile, value);
    ProfileUtils::EntriesToAccessee(value, accessee);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: GetAccessControlProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, GetAccessControlProfile_001, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"userId", "22"}, {"bundleName", "bb1"}, {"bindType", "1"}, {"status", "0"}});
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetAccessControlProfile(parms, profile);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: UpdateAccessControlProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, UpdateAccessControlProfile_001, TestSize.Level1)
{
    AccessControlProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().UpdateAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: DeleteAccessControlProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, DeleteAccessControlProfile_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().DeleteAccessControlProfile(9);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: GetAllAccessControlProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, GetAllAccessControlProfile_001, TestSize.Level1)
{
    std::vector<AccessControlProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetAllAccessControlProfile(profile);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: GetAllTrustDeviceProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, GetAllTrustDeviceProfile_001, TestSize.Level1)
{
    std::vector<TrustDeviceProfile> profile;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetAllTrustDeviceProfile(profile);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

/*
 * @tc.name: GetTrustDeviceProfile_001
 * @tc.desc: Normal testCase of DistributedDeviceProfileClientRdbTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDeviceProfileClientRdbTest, GetTrustDeviceProfile_001, TestSize.Level1)
{
    TrustDeviceProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetTrustDeviceProfile("123456", profile);
    ValuesBucket value;
    ProfileUtils::TrustDeviceProfileToEntries(profile, value);
    ProfileUtils::EntriesToTrustDeviceProfile(value, profile);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}

HWTEST_F(DistributedDeviceProfileClientRdbTest, OnRemoveSystemAbility_001, TestSize.Level1)
{
    TrustDeviceProfile profile;
    int32_t ret = OHOS::DistributedDeviceProfile::DistributedDeviceProfileClient::
        GetInstance().GetTrustDeviceProfile("123456", profile);
    DistributedDeviceProfileClient::SystemAbilityListener saListeneer;
    int32_t systemAbilityId = 1;
    std::string deviceId = "deviceId_test";
    saListeneer.OnRemoveSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(ret, DP_PERMISSION_DENIED);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
