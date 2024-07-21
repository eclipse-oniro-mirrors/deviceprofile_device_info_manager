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
}
}
