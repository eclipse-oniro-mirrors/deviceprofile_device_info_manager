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
#include <gtest/gtest.h>
#include <string>
#include "trust_device_profile.h"
#include "distributed_device_profile_constants.h"
#include "macro_utils.h"
#include "profile_utils.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
const std::string TAG = "TrustDeviceProfileTest";
}
class TrustDeviceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TrustDeviceProfileTest::SetUpTestCase()
{
}

void TrustDeviceProfileTest::TearDownTestCase()
{
}

void TrustDeviceProfileTest::SetUp()
{
}

void TrustDeviceProfileTest::TearDown()
{
}

/*
 * @tc.name: SetDeviceId001
 * @tc.desc: SetDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetDeviceId001, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetDeviceId(deviceId);
    std::string ret = trustDeviceProfile.GetDeviceId();
    EXPECT_EQ(deviceId, ret);
}

/*
 * @tc.name: GetDeviceIdType002
 * @tc.desc: GetDeviceIdType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetDeviceIdType001, TestSize.Level1)
{
    int32_t deviceType = 1;
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetDeviceIdType(deviceType);
    int32_t ret = trustDeviceProfile.GetDeviceIdType();
    EXPECT_EQ(deviceType, ret);
}

/*
 * @tc.name: GetDeviceIdHash001
 * @tc.desc: GetDeviceIdHash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetDeviceIdHash001, TestSize.Level1)
{
    std::string deviceIdHash = "deviceIdHash";
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetDeviceIdHash(deviceIdHash);
    std::string ret = trustDeviceProfile.GetDeviceIdHash();
    EXPECT_EQ(deviceIdHash, ret);
}

/*
 * @tc.name: GetStatus001
 * @tc.desc: GetStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetStatus001, TestSize.Level1)
{
    int32_t status = 1;
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetStatus(status);
    int32_t ret = trustDeviceProfile.GetStatus();
    EXPECT_EQ(status, ret);
}

/*
 * @tc.name: GetStatus001
 * @tc.desc: GetStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetBindType001, TestSize.Level1)
{
    uint32_t bindType = 1;
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetBindType(bindType);
    uint32_t ret = trustDeviceProfile.GetBindType();
    EXPECT_EQ(bindType, ret);
}

/*
 * @tc.name: GetPeerUserId001
 * @tc.desc: GetPeerUserId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetPeerUserId001, TestSize.Level1)
{
    int32_t peerUserId = 100;
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetPeerUserId(peerUserId);
    int32_t ret = trustDeviceProfile.GetPeerUserId();
    EXPECT_EQ(peerUserId, ret);
}

/*
 * @tc.name: GetLocalUserId001
 * @tc.desc: GetLocalUserId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetLocalUserId001, TestSize.Level1)
{
    int32_t localUserId = 200;
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetLocalUserId(localUserId);
    int32_t ret = trustDeviceProfile.GetLocalUserId();
    EXPECT_EQ(localUserId, ret);
}

/*
 * @tc.name: GetPeerAccountId001
 * @tc.desc: GetPeerAccountId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetPeerAccountId001, TestSize.Level1)
{
    std::string peerAccountId = "peerAccountId";
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetPeerAccountId(peerAccountId);
    std::string ret = trustDeviceProfile.GetPeerAccountId();
    EXPECT_EQ(peerAccountId, ret);
}

/*
 * @tc.name: GetLocalAccountId001
 * @tc.desc: GetLocalAccountId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetLocalAccountId001, TestSize.Level1)
{
    std::string localAccountId = "localAccountId";
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetLocalAccountId(localAccountId);
    std::string ret = trustDeviceProfile.GetLocalAccountId();
    EXPECT_EQ(localAccountId, ret);
}

/*
 * @tc.name: GetServiceIdList001
 * @tc.desc: GetServiceIdList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, GetServiceIdList001, TestSize.Level1)
{
    std::vector<int64_t> serviceIdList = {1, 2, 3};
    TrustDeviceProfile trustDeviceProfile;
    trustDeviceProfile.SetServiceIdList(serviceIdList);
    std::vector<int64_t> ret = trustDeviceProfile.GetServiceIdList();
    EXPECT_EQ(serviceIdList, ret);
}

/*
 * @tc.name: Marshalling001
 * @tc.desc: Marshalling and UnMarshalling round-trip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TrustDeviceProfileTest, Marshalling001, TestSize.Level1)
{
    TrustDeviceProfile srcProfile;
    srcProfile.SetDeviceId("deviceId");
    srcProfile.SetDeviceIdType(1);
    srcProfile.SetDeviceIdHash("deviceIdHash");
    srcProfile.SetStatus(2);
    srcProfile.SetBindType(3);
    srcProfile.SetPeerUserId(100);
    srcProfile.SetLocalUserId(200);
    srcProfile.SetPeerAccountId("peerAccountId");
    srcProfile.SetLocalAccountId("localAccountId");
    std::vector<int64_t> serviceIdList = {10, 20, 30};
    srcProfile.SetServiceIdList(serviceIdList);

    MessageParcel parcel;
    EXPECT_TRUE(srcProfile.Marshalling(parcel));

    TrustDeviceProfile dstProfile;
    EXPECT_TRUE(dstProfile.UnMarshalling(parcel));
    EXPECT_EQ(srcProfile.GetDeviceId(), dstProfile.GetDeviceId());
    EXPECT_EQ(srcProfile.GetDeviceIdType(), dstProfile.GetDeviceIdType());
    EXPECT_EQ(srcProfile.GetDeviceIdHash(), dstProfile.GetDeviceIdHash());
    EXPECT_EQ(srcProfile.GetStatus(), dstProfile.GetStatus());
    EXPECT_EQ(srcProfile.GetBindType(), dstProfile.GetBindType());
    EXPECT_EQ(srcProfile.GetPeerUserId(), dstProfile.GetPeerUserId());
    EXPECT_EQ(srcProfile.GetLocalUserId(), dstProfile.GetLocalUserId());
    EXPECT_EQ(srcProfile.GetPeerAccountId(), dstProfile.GetPeerAccountId());
    EXPECT_EQ(srcProfile.GetLocalAccountId(), dstProfile.GetLocalAccountId());
    std::vector<int64_t> dstServiceIdList = dstProfile.GetServiceIdList();
    EXPECT_EQ(serviceIdList, dstServiceIdList);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
