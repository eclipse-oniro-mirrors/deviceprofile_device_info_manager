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
#include "device_profile_storage_manager.h"
#include "distributed_device_profile_client.h"
#include "ipc_skeleton.h"
#include "profile_event.h"
#include "subscribe_info.h"
#include "subscriber_death_recipient.h"
#include "utils.h"

#define private public
#include "profile_event_handler_factory.h"
#include "profile_sync_handler.h"
#include "subscribe_manager.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
    constexpr int32_t MAX_SUBSCRIBS_PER_UID = 100;
}

class SubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SubscribeManagerTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
    DeviceProfileStorageManager::GetInstance().Init();
}

void SubscribeManagerTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void SubscribeManagerTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void SubscribeManagerTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

class StorageProfileEventCallback : public IProfileEventCallback {
};

/**
 * @tc.name: IncSubsOfUidLocked_001
 * @tc.desc: IncSubsOfUidLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, IncSubsOfUidLocked_001, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().IncSubsOfUidLocked(mockUid);
    int32_t expectedCount = SubscribeManager::GetInstance().uidSubsMap_[mockUid];
    EXPECT_EQ(expectedCount, 1);
    SubscribeManager::GetInstance().IncSubsOfUidLocked(mockUid);
    expectedCount = SubscribeManager::GetInstance().uidSubsMap_[mockUid];
    EXPECT_EQ(expectedCount, 2);
    SubscribeManager::GetInstance().uidSubsMap_.clear();
}

/**
 * @tc.name: CheckSubsOfUid_001
 * @tc.desc: IncSubsOfUidLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, CheckSubsOfUid_001, TestSize.Level3)
{
    int32_t mockUid = -1;
    bool ret = SubscribeManager::GetInstance().CheckSubsOfUid(mockUid);
    EXPECT_TRUE(ret);
    SubscribeManager::GetInstance().uidSubsMap_.clear();
}

/**
 * @tc.name: CheckSubsOfUid_002
 * @tc.desc: CheckSubsOfUid
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, CheckSubsOfUid_002, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().IncSubsOfUidLocked(mockUid);
    bool ret = SubscribeManager::GetInstance().CheckSubsOfUid(mockUid);
    EXPECT_TRUE(ret);
    SubscribeManager::GetInstance().uidSubsMap_.clear();
}

/**
 * @tc.name: CheckSubsOfUid_003
 * @tc.desc: CheckSubsOfUid
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, CheckSubsOfUid_003, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().uidSubsMap_[mockUid] = MAX_SUBSCRIBS_PER_UID;
    bool ret = SubscribeManager::GetInstance().CheckSubsOfUid(mockUid);
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().uidSubsMap_.clear();
}

/**
 * @tc.name: DecSubsOfUidLocked_001
 * @tc.desc: DecSubsOfUidLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, DecSubsOfUidLocked_001, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().DecSubsOfUidLocked(mockUid);
    bool ret = SubscribeManager::GetInstance().uidSubsMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DecSubsOfUidLocked_002
 * @tc.desc: DecSubsOfUidLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, DecSubsOfUidLocked_002, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().IncSubsOfUidLocked(mockUid);
    bool ret = SubscribeManager::GetInstance().uidSubsMap_.empty();
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().DecSubsOfUidLocked(mockUid);
    ret = SubscribeManager::GetInstance().uidSubsMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DecSubsOfUidLocked_002
 * @tc.desc: DecSubsOfUidLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, DecSubsOfUidLocked_003, TestSize.Level3)
{
    int32_t mockUid = -1;
    SubscribeManager::GetInstance().uidSubsMap_[mockUid] = MAX_SUBSCRIBS_PER_UID;
    bool ret = SubscribeManager::GetInstance().uidSubsMap_.empty();
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().DecSubsOfUidLocked(mockUid);
    ret = SubscribeManager::GetInstance().uidSubsMap_.empty();
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().uidSubsMap_.clear();
}

/**
 * @tc.name: OnSubscriberDied_001
 * @tc.desc: OnSubscriberDied
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, OnSubscriberDied_001, TestSize.Level3)
{
    sptr<IRemoteObject> object;
    SubscribeManager::GetInstance().OnSubscriberDied(object);
    bool ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Init_001
 * @tc.desc: Init
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, Init_001, TestSize.Level3)
{
    bool ret = SubscribeManager::GetInstance().Init();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: SubscribeProfileEvents_001
 * @tc.desc: SubscribeProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, SubscribeProfileEvents_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    std::list<SubscribeInfo> subscribeInfos;
    std::list<ProfileEvent> failedEvents;
    int32_t ret = SubscribeManager::GetInstance().SubscribeProfileEvents(subscribeInfos, notifier, failedEvents);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SubscribeProfileEvents_001
 * @tc.desc: SubscribeProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, SubscribeProfileEvents_002, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    std::list<SubscribeInfo> subscribeInfos;
    SubscribeInfo eventChange;
    subscribeInfos.emplace_back(eventChange);
    std::list<ProfileEvent> failedEvents;
    int32_t ret = SubscribeManager::GetInstance().SubscribeProfileEvents(subscribeInfos, notifier, failedEvents);
    EXPECT_EQ(ret, ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: SubscribeProfileEvents_003
 * @tc.desc: SubscribeProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, SubscribeProfileEvents_003, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));

    std::list<SubscribeInfo> subscribeInfos;
    SubscribeInfo eventChange;
    eventChange.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    ExtraInfo extraInfo;
    eventChange.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(eventChange);

    std::list<ProfileEvent> failedEvents;

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    SubscribeManager::GetInstance().uidSubsMap_[callingUid] = MAX_SUBSCRIBS_PER_UID;
    int32_t ret = SubscribeManager::GetInstance().SubscribeProfileEvents(subscribeInfos, notifier, failedEvents);
    EXPECT_EQ(ret, ERR_DP_SUBSCRIBE_LIMIT_EXCEEDED);
}

/**
 * @tc.name: UnsubscribeProfileEvents_001
 * @tc.desc: UnsubscribeProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, UnsubscribeProfileEvents_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));

    std::list<ProfileEvent> profileEvents = { ProfileEvent::EVENT_SYNC_COMPLETED };
    std::list<ProfileEvent> failedEvents;

    int32_t ret = SubscribeManager::GetInstance().UnsubscribeProfileEvents(profileEvents, notifier, failedEvents);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TryAddNotifierLocked_001
 * @tc.desc: TryAddNotifierLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, TryAddNotifierLocked_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));

    ProfileEvents subProfileEvents;
    subProfileEvents.set(1);
    ASSERT_TRUE(SubscribeManager::GetInstance().subscriberDeathRecipient_ != nullptr);
    SubscribeManager::GetInstance().TryAddNotifierLocked(notifier, subProfileEvents);
    bool ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().TryAddNotifierLocked(notifier, subProfileEvents);
    SubscribeManager::GetInstance().notifiersMap_.clear();
    ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TryRemoveNotiferLocked_001
 * @tc.desc: TryRemoveNotiferLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, TryRemoveNotiferLocked001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub (syncCb));

    ProfileEvents subProfileEvents;
    subProfileEvents.set(1);
    ASSERT_TRUE(SubscribeManager::GetInstance().subscriberDeathRecipient_ != nullptr);
    SubscribeManager::GetInstance().TryRemoveNotiferLocked(notifier, subProfileEvents);
    bool ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TryRemoveNotiferLocked_002
 * @tc.desc: TryRemoveNotiferLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, TryRemoveNotiferLocked002, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));

    ProfileEvents subProfileEvents;
    subProfileEvents.set(1);
    ASSERT_TRUE(SubscribeManager::GetInstance().subscriberDeathRecipient_ != nullptr);
    SubscribeManager::GetInstance().TryAddNotifierLocked(notifier, subProfileEvents);
    bool ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_FALSE(ret);
    SubscribeManager::GetInstance().TryRemoveNotiferLocked(notifier, subProfileEvents);
    ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TryRemoveNotiferLocked_003
 * @tc.desc: TryRemoveNotiferLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, TryRemoveNotiferLocked003, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));

    ProfileEvents subProfileEvents;
    subProfileEvents.set(1);
    SubscribeManager::GetInstance().TryAddNotifierLocked(notifier, subProfileEvents);
    bool ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_FALSE(ret);
    ProfileEvents unSubProfileEvents;
    unSubProfileEvents.set(0);
    SubscribeManager::GetInstance().TryRemoveNotiferLocked(notifier, unSubProfileEvents);
    ret = SubscribeManager::GetInstance().notifiersMap_.empty();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Unregister_001
 * @tc.desc: Unregister
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, Unregister_001, TestSize.Level3)
{
    auto handler = std::make_shared<ProfileSyncHandler>("syncHandler");
    auto result = handler->Unregister();

    std::map<std::string, Status> syncResult;
    syncResult["testdeviceid"] = Status::SUCCESS;
    handler->SyncCompleted(syncResult);

    SyncResult syncResults;
    syncResults.emplace("testdeviceid", SUCCEEDED);
    handler->NotifySyncCompleted(syncResults);

    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    wptr<IRemoteObject> notifier =
    sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    auto death = std::make_shared<SubscriberDeathRecipient>();
    death->OnRemoteDied(notifier);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: GetProfileChangeHandlerInner_001
 * @tc.desc: GetProfileChangeHandlerInner
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeManagerTest, GetProfileChangeHandlerInner_001, TestSize.Level3)
{
    auto result = ProfileEventHandlerFactory::GetInstance().GetProfileChangeHandlerInner();
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_NE(nullptr, result);
}
}
}
