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
#include <memory>

#include "device_profile_errors.h"
#include "iprofile_event_callback.h"
#include "iprofile_event_notifier.h"
#include "profile_change_notification.h"
#include "profile_event.h"
#include "profile_event_notifier_proxy.h"
#include "profile_event_notifier_stub.h"

#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr int32_t MAX_ENTRY_LEN = 1000001;
}

class ProfileChangeNotificationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class StorageProfileEventCallback : public IProfileEventCallback {
};

void ProfileChangeNotificationTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileChangeNotificationTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileChangeNotificationTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileChangeNotificationTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: GetProfileEntries_001
 * @tc.desc: get profile entries
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, GetProfileEntries_001, TestSize.Level3)
{
    ProfileChangeNotification notification;
    auto result = notification.GetProfileEntries();
    EXPECT_EQ(true, result.empty());
}

/**
 * @tc.name: GetProfileEntries_002
 * @tc.desc: get profile entries
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, GetProfileEntries_002, TestSize.Level3)
{
    std::vector<ProfileEntry> profileEntries;
    std::string networkId;
    bool isLocal = true;
    ProfileChangeNotification notification(profileEntries, networkId, isLocal);
    auto result = notification.GetProfileEntries();
    EXPECT_EQ(true, result.empty());
}

/**
 * @tc.name: GetDeviceId_001
 * @tc.desc: get device id
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, GetDeviceId_001, TestSize.Level3)
{
    std::vector<ProfileEntry> profileEntries;
    std::string networkId;
    bool isLocal = true;
    std::shared_ptr<ProfileChangeNotification> temp =
        std::make_shared<ProfileChangeNotification>(profileEntries, networkId, isLocal);
    std::string result = temp->GetDeviceId();
    EXPECT_EQ("", result);
}

/**
 * @tc.name: IsLocal_001
 * @tc.desc: judge is local
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, IsLocal_001, TestSize.Level3)
{
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->IsLocal();
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: Marshalling_001
 * @tc.desc: marshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Marshalling_001, TestSize.Level3)
{
    Parcel parcel;
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Marshalling(parcel);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: Marshalling_001
 * @tc.desc: marshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Marshalling_002, TestSize.Level3)
{
    ProfileEntry entry;
    std::vector<ProfileEntry> profileEntries(1, entry);
    std::string networkId = "112223";
    bool isLocal = true;
    ProfileChangeNotification notification(profileEntries, networkId, isLocal);
    Parcel parcel;
    bool ret = notification.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: unmarshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Unmarshalling_001, TestSize.Level3)
{
    Parcel parcel;
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: unmarshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Unmarshalling_002, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(-1);
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: unmarshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Unmarshalling_003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(MAX_ENTRY_LEN);
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: unmarshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Unmarshalling_004, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    parcel.WriteString("111");
    parcel.WriteString("222");
    uint8_t type = 1;
    parcel.WriteUint8(type);
    parcel.WriteString("222");
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: unmarshalling of profile change notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, Unmarshalling_005, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    std::shared_ptr<ProfileChangeNotification> temp = std::make_shared<ProfileChangeNotification>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, OnRemoteRequest_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    SyncResult syncResults;
    syncResults.emplace("testdeviceid", SUCCEEDED);
    if (!data.WriteInterfaceToken(ProfileEventNotifierProxy::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(syncResults.size()))) {
        return;
    }

    for (const auto& [deviceId, syncResult] : syncResults) {
        if (!data.WriteString(deviceId) ||
            !data.WriteInt32(static_cast<int32_t>(syncResult))) {
            return;
        }
    }

    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    std::shared_ptr<ProfileEventNotifierStub> temp = std::make_shared<ProfileEventNotifierStub>(syncCb);
    int32_t result = temp->OnRemoteRequest(EVENT_SYNC_COMPLETED, data, reply, option);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_EQ(0, result);
}
/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, OnRemoteRequest_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    if (!data.WriteInterfaceToken(ProfileEventNotifierProxy::GetDescriptor())) {
        return;
    }

    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    std::shared_ptr<ProfileEventNotifierStub> temp = std::make_shared<ProfileEventNotifierStub>(syncCb);
    int32_t result = temp->OnRemoteRequest(EVENT_PROFILE_CHANGED, data, reply, option);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, OnRemoteRequest_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    SyncResult syncResults;
    if (!data.WriteInterfaceToken(ProfileEventNotifierProxy::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(syncResults.size()))) {
        return;
    }

    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    std::shared_ptr<ProfileEventNotifierStub> temp = std::make_shared<ProfileEventNotifierStub>(syncCb);
    int32_t result = temp->OnRemoteRequest(EVENT_SYNC_COMPLETED, data, reply, option);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}
}
}