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
#include "profile_change_listener_proxy.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "rdb_open_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace std;
namespace {
    const std::string TAG = "ProfileChangeListenerProxyTest";
}
class ProfileChangeListenerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileChangeListenerProxyTest::SetUpTestCase()
{
}

void ProfileChangeListenerProxyTest::TearDownTestCase()
{
}

void ProfileChangeListenerProxyTest::SetUp()
{
}

void ProfileChangeListenerProxyTest::TearDown()
{
}

/*
 * @tc.name: OnTrustDeviceProfile_001
 * @tc.desc: Normal testCase of ProfileChangeListenerProxyTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(ProfileChangeListenerProxyTest, OnTrustDeviceProfile_001, TestSize.Level1)
{
    TrustDeviceProfile oldProfile;
    TrustDeviceProfile newProfile;
    OHOS::DistributedDeviceProfile::ProfileListenerProxy proxy(nullptr);
    int32_t ret = proxy.OnTrustDeviceProfileAdd(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnTrustDeviceProfileUpdate(oldProfile, newProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnTrustDeviceProfileDelete(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: OnDeviceProfile_001
 * @tc.desc: Normal testCase of ProfileChangeListenerProxyTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(ProfileChangeListenerProxyTest, OnDeviceProfile_001, TestSize.Level1)
{
    DeviceProfile oldProfile;
    DeviceProfile newProfile;
    OHOS::DistributedDeviceProfile::ProfileListenerProxy proxy(nullptr);
    int32_t ret = proxy.OnDeviceProfileAdd(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnDeviceProfileUpdate(oldProfile, newProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnDeviceProfileDelete(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: OnServiceProfile_001
 * @tc.desc: Normal testCase of ProfileChangeListenerProxyTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(ProfileChangeListenerProxyTest, OnServiceProfile_001, TestSize.Level1)
{
    ServiceProfile oldProfile;
    ServiceProfile newProfile;
    OHOS::DistributedDeviceProfile::ProfileListenerProxy proxy(nullptr);
    int32_t ret = proxy.OnServiceProfileAdd(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnServiceProfileUpdate(oldProfile, newProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnServiceProfileDelete(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/*
 * @tc.name: OnCharacteristicProfile_001
 * @tc.desc: Normal testCase of ProfileChangeListenerProxyTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(ProfileChangeListenerProxyTest, OnCharacteristicProfile_001, TestSize.Level1)
{
    CharacteristicProfile oldProfile;
    CharacteristicProfile newProfile;
    OHOS::DistributedDeviceProfile::ProfileListenerProxy proxy(nullptr);
    int32_t ret = proxy.OnCharacteristicProfileAdd(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnCharacteristicProfileUpdate(oldProfile, newProfile);
    EXPECT_NE(ret, DP_SUCCESS);
    ret = proxy.OnCharacteristicProfileDelete(oldProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
