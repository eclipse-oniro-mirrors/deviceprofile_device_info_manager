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

#include "device_profile_errors.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_service.h"
#include "subscribe_info.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t MAX_EVENT_LEN = 1000001;
const std::u16string DP_INTERFACE_TOKEN = u"OHOS.DeviceProfile.IDistributedDeviceProfile";
}

class DistributedDeviceProfileServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class StorageProfileEventCallback : public IProfileEventCallback {
};


void DistributedDeviceProfileServiceTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void DistributedDeviceProfileServiceTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void DistributedDeviceProfileServiceTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void DistributedDeviceProfileServiceTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: WriteProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, OnRemoteRequest_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = DistributedDeviceProfileService::GetInstance().OnRemoteRequest(0, data, reply, option);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: WriteProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, OnRemoteRequest_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = DistributedDeviceProfileService::GetInstance().OnRemoteRequest(1, data, reply, option);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: PutDeviceProfileInner_001
 * @tc.desc: PutDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, PutDeviceProfileInner_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = DistributedDeviceProfileService::GetInstance().PutDeviceProfileInner(data, reply);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: SubscribeProfileEventInner_001
 * @tc.desc: SubscribeProfileEventInner
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, SubscribeProfileEventInner_001, TestSize.Level3)
{
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    int32_t ret = DistributedDeviceProfileService::GetInstance().GetDeviceProfileInner(data, reply);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: SubscribeProfileEventInner_001
 * @tc.desc: SubscribeProfileEventInner
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, SubscribeProfileEventInner_002, TestSize.Level3)
{
    MessageParcel data;
    data.WriteUint32(MAX_EVENT_LEN);
    MessageParcel reply;
    int32_t ret = DistributedDeviceProfileService::GetInstance().GetDeviceProfileInner(data, reply);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, Dump_001, TestSize.Level3)
{
    std::vector<std::u16string> args;
    int32_t fd = 0;
    int32_t ret = DistributedDeviceProfileService::GetInstance().Dump(fd, args);
    EXPECT_EQ(ERR_DP_FILE_FAILED_ERR, ret);
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, Dump_002, TestSize.Level3)
{
    std::vector<std::u16string> args;
    std::u16string help(u"-h");
    args.emplace_back(help);
    int32_t fd = 0;
    int32_t ret = DistributedDeviceProfileService::GetInstance().Dump(fd, args);
    EXPECT_EQ(ERR_DP_FILE_FAILED_ERR, ret);
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device service without permission
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, PutDeviceProfile_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("");
    int32_t ret = DistributedDeviceProfileService::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: put device service without permission
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, DeleteDeviceProfile_001, TestSize.Level3)
{
    int32_t ret = DistributedDeviceProfileService::GetInstance().DeleteDeviceProfile("");
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: GetDeviceProfile_001
 * @tc.desc: put device service without permission
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, GetDeviceProfile_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("");
    int32_t ret = DistributedDeviceProfileService::GetInstance().GetDeviceProfile("", "", profile);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: SyncDeviceProfile_001
 * @tc.desc: put device service without permission
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DistributedDeviceProfileServiceTest, SyncDeviceProfile_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    SyncOptions syncOptions;
    int32_t ret = DistributedDeviceProfileService::GetInstance().SyncDeviceProfile(syncOptions, notifier);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, ret);
}
}
}