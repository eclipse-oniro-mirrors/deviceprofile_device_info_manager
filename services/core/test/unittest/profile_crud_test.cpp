/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "utils.h"
#include "test_util.h"

#define private public
#define protected public
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "distributed_device_profile_client.h"
#include "hisysevent.h"
#include "nlohmann/json.hpp"
#include "syscap_info_collector.h"
#include "syscap_interface.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::HiviewDFX;
namespace {
    const std::string TAG = "SyscapInfoCollector";
    const std::string SERVICE_ID = "syscap";
    const std::string SERVICE_TYPE = "syscap";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    const std::string DEVICE_PROFILE_SYNC_FAILED = "DEVICE_PROFILE_SYNC_FAILED";
    const std::string FAULT_CODE_KEY = "FAULT_CODE";
    const std::string DOMAIN_NAME = std::string(HiSysEvent::Domain::DEVICE_PROFILE);
}
using namespace testing;
using namespace testing::ext;

class ProfileCrudTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileCrudTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileCrudTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileCrudTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileCrudTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

class ProfileEventCallback : public IProfileEventCallback {
public:
    ProfileEventCallback() = default;
    ~ProfileEventCallback() = default;

    void OnSyncCompleted(const SyncResult& syncResults) override
    {
    }

    void OnProfileChanged(const ProfileChangeNotification& changeNotification) override
    {
        if (!subServiceIds_.empty()) {
            const auto& profileEntries = changeNotification.GetProfileEntries();
            for (const auto& ProfileEntry : profileEntries) {
                auto key = ProfileEntry.key;
                DTEST_LOG << "key: " << key << std::endl;
                numNotifications_++;
            }
        }
    }

    void SetSubServiceIds(const std::list<std::string>& subServiceIds)
    {
        subServiceIds_ = subServiceIds;
    }

    int32_t GetNotificationNum() const
    {
        return numNotifications_;
    }

private:
    std::list<std::string> subServiceIds_;
    int32_t numNotifications_ {0};
};

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_002
 * @tc.desc: put device profile with empty service type
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_002, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_003
 * @tc.desc: put device profile with empty characteristics
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_003, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    // the result string is "null"
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_004
 * @tc.desc: put device profile without set characteristics
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_004, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_005
 * @tc.desc: put device profile without set characteristics
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_005, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, result);
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileCrudTest, DeleteDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    int32_t result = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile("");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: DeleteDeviceProfile_002
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileCrudTest, DeleteDeviceProfile_002, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    int32_t result = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, result);
}

/**
 * @tc.name: SubscribeProfileEvent_001
 * @tc.desc: subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvent_001, TestSize.Level3)
{
    auto eventCb = std::make_shared<ProfileEventCallback>();
    if (eventCb == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    SubscribeInfo subscribeInfo;
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvent(subscribeInfo, eventCb);
    EXPECT_NE(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SyncDeviceProfile_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SyncDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    wptr<IRemoteObject> remote;
    DistributedDeviceProfileClient::DeviceProfileDeathRecipient obj;
    obj.OnRemoteDied(remote);
    auto syncCb = std::make_shared<ProfileEventCallback>();
    SyncOptions syncOptions;
    int result = DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, result);
}

/**
 * @tc.name: UnsubscribeProfileEvent_001
 * @tc.desc: unsubscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnsubscribeProfileEvent_001, TestSize.Level3)
{
    auto eventCb = std::make_shared<ProfileEventCallback>();
    if (eventCb == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    Parcel parcel;
    ProfileEvent profileEvent = static_cast<ProfileEvent>(parcel.ReadUint32());
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvent(profileEvent, eventCb);
    EXPECT_NE(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_001
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<SubscribeInfo> subscribeInfos;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> failedEvents;
    if (subscribeInfos.empty() || eventCb == nullptr) {
        return;
    }
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_002
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_002, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<SubscribeInfo> subscribeInfos;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_003
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_003, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<SubscribeInfo> subscribeInfos;
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos,
        nullptr, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_004
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_004, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<SubscribeInfo> subscribeInfos;
    SubscribeInfo subscribeInfo;
    subscribeInfos.emplace_back(subscribeInfo);
    std::list<ProfileEvent> failedEvents;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(7, result);
}

/**
 * @tc.name: SubscribeProfileEvents_005
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_005, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<SubscribeInfo> subscribeInfos;
    SubscribeInfo subscribeInfo;
    subscribeInfos.emplace_back(subscribeInfo);
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos,
        nullptr, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_006
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_006, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<SubscribeInfo> subscribeInfos;
    std::list<std::string> serviceIds;
    serviceIds.emplace_back("test");
    std::string deviceId = "test";
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo info1;
    info1.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    info1.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(info1);

    SubscribeInfo info2;
    info2.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(info2);

    std::list<ProfileEvent> failedEvents;
    int result =
        DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);
    EXPECT_EQ(ERR_DP_SUBSCRIBE_FAILED, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_001
 * @tc.desc: Unsubscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnsubscribeProfileEvents_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<ProfileEvent> profileEvents;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> failedEvents;
    if (profileEvents.empty() || eventCb == nullptr) {
        return;
    }
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents,
        eventCb, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_002
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnsubscribeProfileEvents_002, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<ProfileEvent> subscribeInfos;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_003
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnsubscribeProfileEvents_003, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }
    std::list<SubscribeInfo> subscribeInfos1;
    std::list<SubscribeInfo> newSubscribeInfos1;
    SubscribeInfo subscribeInfo1;
    SubscribeInfo subscribeInfo2;
    subscribeInfos1.emplace_back(subscribeInfo1);
    newSubscribeInfos1.emplace_back(subscribeInfo2);
    DistributedDeviceProfileClient::GetInstance().MergeSubscribeInfoLocked(subscribeInfos1, newSubscribeInfos1);
    std::list<ProfileEvent> subscribeInfos;
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(subscribeInfos,
        nullptr, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_004
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnsubscribeProfileEvents_004, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }
    std::list<SubscribeInfo> subscribeInfos1;
    std::list<SubscribeInfo> newSubscribeInfos1;
    SubscribeInfo subscribeInfo;
    SubscribeInfo subscribeInfo11;
    subscribeInfos1.emplace_back(subscribeInfo);
    newSubscribeInfos1.emplace_back(subscribeInfo);
    DistributedDeviceProfileClient::GetInstance().MergeSubscribeInfoLocked(subscribeInfos1, newSubscribeInfos1);
    newSubscribeInfos1.clear();
    newSubscribeInfos1.emplace_back(subscribeInfo11);
    DistributedDeviceProfileClient::GetInstance().MergeSubscribeInfoLocked(subscribeInfos1, newSubscribeInfos1);
    std::list<ProfileEvent> subscribeInfos;
    ProfileEvent subscribeInfo1;
    subscribeInfos.emplace_back(subscribeInfo1);
    std::list<ProfileEvent> failedEvents;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(ERR_DP_NOT_SUBSCRIBED, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_005
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnSubscribeProfileEvents_005, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }
    std::list<SubscribeInfo> subscribeInfos;
    std::list<SubscribeInfo> newSubscribeInfos;
    DistributedDeviceProfileClient::GetInstance().MergeSubscribeInfoLocked(subscribeInfos, newSubscribeInfos);
    std::list<ProfileEvent> profileEvents;
    ProfileEvent profileEvent;
    profileEvents.emplace_back(profileEvent);
    std::list<ProfileEvent> failedEvents;
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents,
        nullptr, failedEvents);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_006
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnSubscribeProfileEvents_006, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    std::list<ProfileEvent> subscribeInfos;
    ProfileEvent subscribeInfo;
    subscribeInfos.emplace_back(subscribeInfo);
    std::list<ProfileEvent> failedEvents;
    auto eventCb = std::make_shared<ProfileEventCallback>();
    DistributedDeviceProfileClient::SubscribeRecord subscribeRecord;
    DistributedDeviceProfileClient::GetInstance().subscribeRecords_[eventCb] = subscribeRecord;
    int result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(subscribeInfos,
        eventCb, failedEvents);
    EXPECT_EQ(3, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_007
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnSubscribeProfileEvents_007, TestSize.Level3)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> profileEvents;
    SubscribeInfo info1;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    profileEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    std::list<ProfileEvent> failedEvents;
    int result =
        DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents, callback, failedEvents);
    EXPECT_EQ(ERR_DP_NOT_SUBSCRIBED, result);
}

/**
 * @tc.name: GetDeviceProfile_001
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_001, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    int32_t result = DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", SERVICE_ID, profile);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, result);

    std::string jsonData = profile.GetCharacteristicProfileJson();
    DTEST_LOG << "jsonData:" << jsonData << std::endl;
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData, nullptr, false);
    if (jsonObject.is_discarded()) {
        DTEST_LOG << "json parse faild" << std::endl;
        return;
    }

    std::vector<int> values = jsonObject[CHARACTER_OS_SYSCAP].get<std::vector<int>>();
    int intValues[PCID_MAIN_INTS];
    int i = 0;
    for (int value : values) {
        intValues[i++] = value;
    }

    char (*osOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    int32_t length;
    if (!DecodeOsSyscap((char *)intValues, &osOutput, &length)) {
        DTEST_LOG << "DecodeOsSyscap failed" << std::endl;
        return;
    }
    for (int i = 0; i < length; i++) {
        DTEST_LOG << "OsSyscap: " << *(osOutput + i) << std::endl;
    }

    std::string capabilities = jsonObject[CHARACTER_PRIVATE_SYSCAP];
    char (*priOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    if (!DecodePrivateSyscap((char *)capabilities.c_str(), &priOutput, &length)) {
        DTEST_LOG << "DecodePrivateSyscap failed" << std::endl;
        return;
    }
    for (int i = 0; i < length; i++) {
        DTEST_LOG << "PrivateSyscap: " << *(priOutput + i) << std::endl;
    }
}

/**
 * @tc.name: GetDeviceProfile_002
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4NY22
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_002, TestSize.Level3)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", SERVICE_ID, profile);
    EXPECT_NE(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: DfxErrorPrint_001
 * @tc.desc: print hisysevent error event
 * @tc.type: FUNC
 * @tc.require: I5EE0Y
 */
HWTEST_F(ProfileCrudTest, DfxErrorPrint_001, TestSize.Level3)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, DEVICE_PROFILE_SYNC_FAILED,
        HiSysEvent::EventType::FAULT, FAULT_CODE_KEY, -1);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: SubscribeProfileEvents_007
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_007, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<SubscribeInfo> subscribeInfos;
    std::list<std::string> serviceIds;
    serviceIds.emplace_back("appInfo");
    std::string deviceId = "";
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo info1;
    info1.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    info1.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(info1);

    SubscribeInfo info2;
    info2.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(info2);

    std::list<ProfileEvent> failedEvents;
    int result =
        DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_008
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnSubscribeProfileEvents_008, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> profileEvents;
    SubscribeInfo info1;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    profileEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    std::list<ProfileEvent> failedEvents;
    int result =
        DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents, callback, failedEvents);
    EXPECT_EQ(ERR_DP_NOT_SUBSCRIBED, result);
}

/**
 * @tc.name: UnsubscribeProfileEvents_009
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, UnSubscribeProfileEvents_009, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<SubscribeInfo> subscribeInfos;
    std::list<std::string> serviceIds;
    serviceIds.emplace_back("appInfo");
    std::string deviceId = "";
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo info1;
    info1.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    info1.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(info1);

    SubscribeInfo info2;
    info2.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(info2);

    std::list<ProfileEvent> failedEvents;
    int result =
        DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    profileEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    result =
        DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents, callback, failedEvents);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: SyncDeviceProfile_002
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SyncDeviceProfile_002, TestSize.Level3)
{
    TestUtil::MockPermission("multimodalinput");
    int64_t mode = 2;
    SyncOptions syncOption;
    syncOption.SetSyncMode((OHOS::DeviceProfile::SyncMode)mode);
    syncOption.AddDevice("test");
    int result = DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOption,
        std::make_shared<ProfileEventCallback>());
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_006
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_006, TestSize.Level3)
{
    TestUtil::MockPermission("multimodalinput");
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("InputDeviceCooperation");
    profile.SetServiceType("InputDeviceCooperation");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: GetDeviceProfile_003
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4NY22
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_003, TestSize.Level3)
{
    TestUtil::MockPermission("multimodalinput");
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("InputDeviceCooperation");
    profile.SetServiceType("InputDeviceCooperation");
    nlohmann::json j;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result =
        DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", "InputDeviceCooperation", profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: DeleteDeviceProfile_003
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileCrudTest, DeleteDeviceProfile_003, TestSize.Level3)
{
    TestUtil::MockPermission("multimodalinput");
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    int32_t result = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile("InputDeviceCooperation");
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_007
 * @tc.desc: put device profile with empty service type
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_007, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    profile.SetServiceProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_NE(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_008
 * @tc.desc: put device profile with empty service type
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_008, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    profile.SetServiceProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_NE(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SubscribeProfileEvents_008
 * @tc.desc: Subscribe device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileCrudTest, SubscribeProfileEvents_008, TestSize.Level3)
{
    TestUtil::MockPermission("distributedsched");
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<SubscribeInfo> subscribeInfos;
    std::list<std::string> serviceIds;
    serviceIds.emplace_back("appInfo");
    std::string deviceId = "";
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo info1;
    info1.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    info1.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(info1);

    SubscribeInfo info2;
    info2.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(info2);

    std::list<ProfileEvent> failedEvents;
    DistributedDeviceProfileClient::SubscribeRecord subscribeRecord;
    subscribeRecord.subscribeInfos = subscribeInfos;
    subscribeRecord.notifier = sptr<ProfileEventNotifierStub>(
        new ProfileEventNotifierStub(callback));
    subscribeRecord.profileEvents.set(static_cast<uint32_t>(ProfileEvent::EVENT_PROFILE_CHANGED));
    DistributedDeviceProfileClient::GetInstance().subscribeRecords_[callback] = subscribeRecord;
    int result =
        DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);
    EXPECT_EQ(0, result);
}
}
}