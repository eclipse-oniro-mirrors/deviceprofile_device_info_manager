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

#include "ipc_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"


using namespace testing::ext;
using namespace OHOS::DistributedDeviceProfile;
using namespace std;
namespace {
    const std::string TAG = "IpcUtilsTest";
}
class IpcUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IpcUtilsTest::SetUpTestCase()
{
}

void IpcUtilsTest::TearDownTestCase()
{
}

void IpcUtilsTest::SetUp()
{
}

void IpcUtilsTest::TearDown()
{
}

/*
 * @tc.name: Marshalling_001
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_001, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::vector<TrustDeviceProfile> profiles;
    bool ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    TrustDeviceProfile trustProfile;
    profiles.push_back(trustProfile);
    ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: Marshalling_002
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_002, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::vector<AccessControlProfile> profiles;
    bool ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    AccessControlProfile aclProfile;
    profiles.push_back(aclProfile);
    ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: Marshalling_003
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_003, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::vector<ServiceProfile> profiles;
    bool ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    ServiceProfile serviceProfile;
    profiles.push_back(serviceProfile);
    ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: Marshalling_004
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_004, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::vector<CharacteristicProfile> profiles;
    bool ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, false);
    CharacteristicProfile chacProfile;
    profiles.push_back(chacProfile);
    ret = IpcUtils::Marshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, profiles);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: Marshalling_005
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_005, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::map<std::string, std::string> params;
    bool ret = IpcUtils::Marshalling(parcel, params);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, params);
    EXPECT_EQ(ret, false);
    params.insert({"userId", "u1"});
    ret = IpcUtils::Marshalling(parcel, params);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, params);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: Marshalling_006
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_006, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::map<std::string, OHOS::DistributedDeviceProfile::SubscribeInfo> listenerMap;
    bool ret = IpcUtils::Marshalling(parcel, listenerMap);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, listenerMap);
    EXPECT_EQ(ret, false);
    SubscribeInfo subscribeInfo;
    listenerMap.insert({"12345", subscribeInfo});
    ret = IpcUtils::Marshalling(parcel, listenerMap);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, listenerMap);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: Marshalling_007
 * @tc.desc: Normal testCase of IpcUtilsTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(IpcUtilsTest, Marshalling_007, TestSize.Level1)
{
    OHOS::MessageParcel parcel;
    std::unordered_set<ProfileChangeType> changeTypes;
    bool ret = IpcUtils::Marshalling(parcel, changeTypes);
    EXPECT_EQ(ret, false);
    ret = IpcUtils::UnMarshalling(parcel, changeTypes);
    EXPECT_EQ(ret, false);
    changeTypes.insert(ProfileChangeType::TRUST_DEVICE_PROFILE_ADD);
    changeTypes.insert(ProfileChangeType::TRUST_DEVICE_PROFILE_UPDATE);
    changeTypes.insert(ProfileChangeType::TRUST_DEVICE_PROFILE_DELETE);
    ret = IpcUtils::Marshalling(parcel, changeTypes);
    EXPECT_EQ(ret, true);
    ret = IpcUtils::UnMarshalling(parcel, changeTypes);
    EXPECT_EQ(ret, true);
}