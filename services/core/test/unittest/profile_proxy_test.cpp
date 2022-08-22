/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "utils.h"

#define private public
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_proxy.h"
#include "iprofile_event_callback.h"
#undef private

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileProxyTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileProxyTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileProxyTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileProxyTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with test service
 * @tc.type: FUNC
 * @tc.require: I51HKG
 */
HWTEST_F(ProfileProxyTest, PutDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        return;
    }

    SyncResult syncResults;
    IProfileEventCallback eventCb;
    eventCb.OnSyncCompleted(syncResults);
    DTEST_LOG << "sync results completed" << std::endl;

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json jsonData;
    profile.SetCharacteristicProfileJson(jsonData.dump());
    int32_t result = dps->PutDeviceProfile(profile);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_NE(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I51HKG
 */
HWTEST_F(ProfileProxyTest, DeleteDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        return;
    }

    std::string serviceId = "";
    int32_t result = dps->DeleteDeviceProfile(serviceId);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_NE(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: SyncDeviceProfile_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I51HKG
 */
HWTEST_F(ProfileProxyTest, SyncDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        return;
    }

    ProfileChangeNotification changeNotification;
    IProfileEventCallback eventCb;
    eventCb.OnProfileChanged(changeNotification);
    DTEST_LOG << "profile changed" << std::endl;

    SyncOptions syncOptions;
    sptr<IRemoteObject> profileEventNotifier;
    int32_t result = dps->SyncDeviceProfile(syncOptions, profileEventNotifier);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_NE(result, ERR_INVALID_DATA);
}
}
}