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
#include "profile_change_notification.h"
#include "subscribe_info.h"
#include "utils.h"

#define private public
#define protected public
#include "dp_device_manager.h"
#include "profile_change_handler.h"
#include "profile_event_handler.h"
#include "profile_sync_handler.h"
#include "sync_coordinator.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileChangeHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<ProfileChangeHandler> profileChangeHandler_;
};

class StorageProfileEventCallback : public IProfileEventCallback {
};

void ProfileChangeHandlerTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileChangeHandlerTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileChangeHandlerTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
    if (profileChangeHandler_ == nullptr) {
        profileChangeHandler_ = std::make_shared<ProfileChangeHandler>("profileChangeTest");
    }
}

void ProfileChangeHandlerTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}


/**
 * @tc.name: ConvertEntry_001
 * @tc.desc: ConvertEntry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, ConvertEntry_001, TestSize.Level3)
{
    DistributedKv::Entry entry1;
    entry1.key = "key";
    entry1.value = "value";
    std::vector<DistributedKv::Entry> inserts;
    inserts.emplace_back(entry1);
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
    std::vector<ProfileEntry> filteredEntries;
    Service2Index service2Index;
    profileChangeHandler_->ConvertEntry(inserts, changeType, filteredEntries, service2Index);
    EXPECT_TRUE(filteredEntries.empty());
}

/**
 * @tc.name: ConvertEntry_002
 * @tc.desc: ConvertEntry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, ConvertEntry_002, TestSize.Level3)
{
    DistributedKv::Entry entry1;
    entry1.key = "key/key/key";
    entry1.value = "value";
    std::vector<DistributedKv::Entry> inserts;
    inserts.emplace_back(entry1);
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
    std::vector<ProfileEntry> filteredEntries;
    Service2Index service2Index;
    profileChangeHandler_->ConvertEntry(inserts, changeType, filteredEntries, service2Index);
    EXPECT_TRUE(filteredEntries.empty());
}

/**
 * @tc.name: ConvertEntry_003
 * @tc.desc: ConvertEntry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, ConvertEntry_003, TestSize.Level3)
{
    DistributedKv::Entry entry1;
    entry1.key = "1234567812345678123456781234567812345678123456781234567812345678/key/key";
    entry1.value = "value";
    std::vector<DistributedKv::Entry> inserts;
    inserts.emplace_back(entry1);
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
    std::vector<ProfileEntry> filteredEntries;
    Service2Index service2Index;
    profileChangeHandler_->ConvertEntry(inserts, changeType, filteredEntries, service2Index);
    EXPECT_TRUE(filteredEntries.empty());
}

/**
 * @tc.name: ConvertEntry_004
 * @tc.desc: ConvertEntry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, ConvertEntry_004, TestSize.Level3)
{
    DistributedKv::Entry entry1;
    entry1.key = "1234567812345678123456781234567812345678123456781234567812345678/1/key";
    entry1.value = "value";
    std::vector<DistributedKv::Entry> inserts;
    inserts.emplace_back(entry1);
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
    std::vector<ProfileEntry> filteredEntries;
    Service2Index service2Index;
    profileChangeHandler_->ConvertEntry(inserts, changeType, filteredEntries, service2Index);
    EXPECT_TRUE(filteredEntries.empty());
}

/**
 * @tc.name: ConvertEntry_005
 * @tc.desc: ConvertEntry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, ConvertEntry_005, TestSize.Level3)
{
    DistributedKv::Entry entry1;
    entry1.key = "1234567812345678123456781234567812345678123456781234567812345678/0/1";
    entry1.value = "value";
    std::vector<DistributedKv::Entry> inserts;
    inserts.emplace_back(entry1);
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
    std::vector<ProfileEntry> filteredEntries;
    Service2Index service2Index;
    profileChangeHandler_->ConvertEntry(inserts, changeType, filteredEntries, service2Index);
    EXPECT_FALSE(filteredEntries.empty());
    EXPECT_FALSE(service2Index.empty());
}

/**
 * @tc.name: Subscribe_001
 * @tc.desc: Subscribe
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, Subscribe_001, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {{"serviceIds", "1111"}};
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    int32_t ret = profileChangeHandler_->Subscribe(subInfo, notifier);
    ASSERT_EQ(ret, ERR_DP_PERMISSION_DENIED);
}

/**
 * @tc.name: FilterChangedProfileLocked_001
 * @tc.desc: FilterChangedProfileLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, FilterChangedProfileLocked_001, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", {}}
    };
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    Service2Index service2Index;
    profileChangeHandler_->FilterChangedProfileLocked(subInfo, profileNotification,
        service2Index, filterInfo);
    ASSERT_FALSE(filterInfo.filtered);
}

/**
 * @tc.name: FilterChangedProfileLocked_002
 * @tc.desc: FilterChangedProfileLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, FilterChangedProfileLocked_002, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", "111"}
    };
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    Service2Index service2Index;
    profileChangeHandler_->FilterChangedProfileLocked(subInfo, profileNotification,
        service2Index, filterInfo);
    ASSERT_TRUE(filterInfo.filtered);
}

/**
 * @tc.name: FilterChangedProfileLocked_003
 * @tc.desc: FilterChangedProfileLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, FilterChangedProfileLocked_003, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", ""}
    };
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    Service2Index service2Index;
    profileChangeHandler_->FilterChangedProfileLocked(subInfo, profileNotification,
        service2Index, filterInfo);
    ASSERT_TRUE(filterInfo.filtered);
}

/**
 * @tc.name: FilterChangedProfileLocked_004
 * @tc.desc: FilterChangedProfileLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, FilterChangedProfileLocked_004, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", "1111"}
    };
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    Service2Index service2Index;
    profileChangeHandler_->FilterChangedProfileLocked(subInfo, profileNotification,
        service2Index, filterInfo);
    ASSERT_TRUE(filterInfo.filtered);
}

/**
 * @tc.name: FilterChangedProfileLocked_005
 * @tc.desc: FilterChangedProfileLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, FilterChangedProfileLocked_005, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", "1111"}
    };
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    Service2Index service2Index = {{"1111", 1}};
    profileChangeHandler_->FilterChangedProfileLocked(subInfo, profileNotification,
        service2Index, filterInfo);
    ASSERT_TRUE(filterInfo.filtered);
    ASSERT_FALSE(filterInfo.indexes.empty());
}

/**
 * @tc.name: NotifyProfileChangedLocked_001
 * @tc.desc: NotifyProfileChangedLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, NotifyProfileChangedLocked_001, TestSize.Level3)
{
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IProfileEventNotifier> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    profileChangeHandler_->NotifyProfileChangedLocked(profileNotification, filterInfo, notifier);
    ASSERT_FALSE(filterInfo.filtered);
}

/**
 * @tc.name: NotifyProfileChangedLocked_002
 * @tc.desc: NotifyProfileChangedLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, NotifyProfileChangedLocked_002, TestSize.Level3)
{
    ProfileChangeNotification profileNotification;
    FilterInfo filterInfo;
    filterInfo.filtered = true;
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IProfileEventNotifier> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    profileChangeHandler_->NotifyProfileChangedLocked(profileNotification, filterInfo, notifier);
    ASSERT_TRUE(filterInfo.indexes.empty());
}

/**
 * @tc.name: NotifyProfileChangedLocked_003
 * @tc.desc: NotifyProfileChangedLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, NotifyProfileChangedLocked_003, TestSize.Level3)
{
    ProfileEntry entry;
    std::vector<ProfileEntry> entries(1, entry);
    std::string networkId = "1";
    ProfileChangeNotification profileNotification(entries, networkId, true);
    FilterInfo filterInfo;
    filterInfo.filtered = true;
    filterInfo.indexes.emplace(0);
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IProfileEventNotifier> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    profileChangeHandler_->NotifyProfileChangedLocked(profileNotification, filterInfo, notifier);
    ASSERT_FALSE(filterInfo.indexes.empty());
}

/**
 * @tc.name: NotifyProfileChanged_001
 * @tc.desc: NotifyProfileChanged
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, NotifyProfileChanged_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", "1111"}
    };
    
    profileChangeHandler_->profileEventSubscribeInfos_[notifier] = subInfo;
    Service2Index service2Index;
    ProfileChangeNotification profileNotification;
    profileChangeHandler_->NotifyProfileChanged(profileNotification, service2Index);
    ASSERT_TRUE(service2Index.empty());
}

/**
 * @tc.name: OnChange_001
 * @tc.desc: OnChange
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, OnChange_001, TestSize.Level3)
{
    std::shared_ptr<ProfileSyncHandler> profileSyncHandler_ =
        std::make_shared<ProfileSyncHandler>("profileSyncTest");
    std::vector<std::string> deviceIds = {"", std::move("testudid123"), ""};
    std::map<std::string, DistributedKv::Status> results;
    SyncCoordinator::GetInstance().Init();
    SyncCoordinator::GetInstance().isOnlineTrigger_ = false;
    profileSyncHandler_->SyncCompleted(results);
    SyncCoordinator::GetInstance().isOnlineTrigger_ = true;
    profileSyncHandler_->SyncCompleted(results);
    results["success123"] = Status::SUCCESS;
    results["test1"] = Status::ERROR;
    profileSyncHandler_->SyncCompleted(results);
    results.clear();
    results["success123"] = Status::SUCCESS;
    results["test1"] = Status::ERROR;
    results["test2"] = Status::ERROR;
    results["test3"] = Status::ERROR;
    results["test4"] = Status::ERROR;
    std::vector<std::string> deviceIds1;
    deviceIds1.emplace_back("test1");
    deviceIds1.emplace_back("test2");
    deviceIds1.emplace_back("test3");
    deviceIds1.emplace_back("test4");
    DpDeviceManager::GetInstance().deviceIdsList_.emplace_back(deviceIds1);
    profileSyncHandler_->SyncCompleted(results);
    DistributedKv::ChangeNotification profileNotification({}, {}, {}, "", true);
    profileChangeHandler_->OnChange(profileNotification);
    ASSERT_TRUE(profileChangeHandler_->profileEventSubscribeInfos_.empty());
}

/**
 * @tc.name: OnChange_002
 * @tc.desc: OnChange
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeHandlerTest, OnChange_002, TestSize.Level3)
{
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    entry.key = "key";
    entry.value = "value";
    insertEntries.emplace_back(entry);
    updateEntries.emplace_back(entry);
    deleteEntries.emplace_back(entry);
    std::string deviceId = "device";
    DistributedKv::ChangeNotification profileNotification(std::move(insertEntries), std::move(updateEntries),
        std::move(deleteEntries), deviceId, false);
    profileChangeHandler_->OnChange(profileNotification);
    ASSERT_TRUE(profileChangeHandler_->profileEventSubscribeInfos_.empty());
}
}
}