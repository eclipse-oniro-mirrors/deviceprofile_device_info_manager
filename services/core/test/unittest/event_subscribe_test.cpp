/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <thread>

#include "utils.h"

#include "device_profile_errors.h"
#include "distributed_device_profile_client.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
using namespace std::chrono_literals;
using namespace testing;
using namespace testing::ext;

class EventSubscribeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EventSubscribeTest::SetUpTestCase()
{
}

void EventSubscribeTest::TearDownTestCase()
{
}

void EventSubscribeTest::SetUp()
{
}

void EventSubscribeTest::TearDown()
{
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
                auto iter = std::find(subServiceIds_.begin(), subServiceIds_.end(), key);
                EXPECT_TRUE(iter != subServiceIds_.end());
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

int32_t PutFakeStorage()
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("fakeStorage");
    profile.SetServiceType("fakeStorage");
    nlohmann::json j;
    j["capacity"] = 0;
    profile.SetCharacteristicProfileJson(j.dump());
    return DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
}

int32_t PutFakeSystem()
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("fakeSystem");
    profile.SetServiceType("fakeSystem");
    nlohmann::json j;
    j["harmonyVersion"] = "2.2.0";
    profile.SetCharacteristicProfileJson(j.dump());
    return DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
}

int32_t MockSubscribeEvents(const std::shared_ptr<ProfileEventCallback>& eventCb,
    const std::list<std::string>& serviceIds, const std::string& deviceId)
{
    eventCb->SetSubServiceIds(serviceIds);
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    std::list<SubscribeInfo> subscribeInfos;
    SubscribeInfo eventChange;
    eventChange.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    eventChange.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(eventChange);

    SubscribeInfo eventSync;
    eventSync.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    subscribeInfos.emplace_back(eventSync);

    std::list<ProfileEvent> failedEvents;
    return DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(
        subscribeInfos, eventCb, failedEvents);
}

int32_t MockUnsubscribeEvents(const std::shared_ptr<ProfileEventCallback>& eventCb)
{
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    profileEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    std::list<ProfileEvent> failedEvents;
    return DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(
        profileEvents, eventCb, failedEvents);
}

int32_t MockSubscribeEvent(const std::shared_ptr<ProfileEventCallback>& eventCb,
    const std::list<std::string>& serviceIds, const std::string& deviceId)
{
    eventCb->SetSubServiceIds(serviceIds);
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo subscribeInfo;
    subscribeInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    subscribeInfo.extraInfo = std::move(extraInfo);
    return DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvent(subscribeInfo, eventCb);
}

/**
 * @tc.name: Subscribe001
 * @tc.desc: subscribe a service and put a service profile
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe001, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    if (MockSubscribeEvent(callback, {"fakeStorage"}, "")) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }

    int32_t errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }
}

/**
 * @tc.name: Subscribe002
 * @tc.desc: subscribe a service and put a unsubscribed service
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe002, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    if (MockSubscribeEvent(callback, {"fakeSystem"}, "")) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }
    int32_t errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 0);
    }
}

/**
 * @tc.name: Subscribe003
 * @tc.desc: subscribe services and put service
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe003, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    if (MockSubscribeEvents(callback, serviceIds, "") != ERR_OK) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }
    int32_t errCode = PutFakeSystem();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }
}

/**
 * @tc.name: Subscribe004
 * @tc.desc: subscribe with invalid deviceId
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe004, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    if (MockSubscribeEvent(callback, serviceIds, "fake_device_id") != ERR_OK) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }
    int32_t errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 0);
    }
}

/**
 * @tc.name: Subscribe005
 * @tc.desc: subscribe services and put services
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe005, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    /**
     * @tc.steps: step1. subscribe change event with two services
     */
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    if (MockSubscribeEvent(callback, serviceIds, "") != ERR_OK) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }

    /**
     * @tc.steps: step2. put service profile which is subscribed
     * @tc.expected: step2. got one notification.
     */
    int32_t errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }
    /**
     * @tc.steps: step3. put the other subscribed service profile
     * @tc.expected: step3. got notification again.
     */
    errCode = PutFakeSystem();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 2);
    }
}

/**
 * @tc.name: Subscribe006
 * @tc.desc: subscribe with duplicated events
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Subscribe006, TestSize.Level0)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<SubscribeInfo> subscribeInfos;
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = "";
    extraInfo["serviceIds"] = {"fakeSystem"};

    SubscribeInfo eventChange;
    eventChange.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    eventChange.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(eventChange);
    subscribeInfos.emplace_back(eventChange);

    std::list<ProfileEvent> failedEvents;
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(
        subscribeInfos, callback, failedEvents);
    EXPECT_TRUE(errCode == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: Unsubscribe001
 * @tc.desc: unsubscribe event which is not subscribed yet
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Unsubscribe001, TestSize.Level0)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvent(
        ProfileEvent::EVENT_PROFILE_CHANGED, callback);
    EXPECT_TRUE(errCode == ERR_DP_NOT_SUBSCRIBED);
}

/**
 * @tc.name: Unsubscribe002
 * @tc.desc: unsubscribe events which are not subscribed yet
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, Unsubscribe002, TestSize.Level0)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    int32_t errCode = MockUnsubscribeEvents(callback);
    EXPECT_TRUE(errCode == ERR_DP_NOT_SUBSCRIBED);
}

/**
 * @tc.name: SubscribeWithUnsusbscribe001
 * @tc.desc: subscribe events and then unsubscribe one
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, SubscribeWithUnsusbscribe001, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();

    /**
     * @tc.steps: step1. subscribe sync and change event
     */
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    if (MockSubscribeEvents(callback, serviceIds, "") != ERR_OK) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }

    /**
     * @tc.steps: step2. put service profile which is subscribed
     * @tc.expected: step2. got one notification.
     */
    int32_t errCode = PutFakeSystem();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }

    /**
     * @tc.steps: step3. unsubscribe sync event
     */
    errCode = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvent(
        ProfileEvent::EVENT_SYNC_COMPLETED, callback);
    if (errCode != ERR_OK) {
        DTEST_LOG << "unsubscribe failed" << std::endl;
        return;
    }

    /**
     * @tc.steps: step4. put the other subscribed service profile
     * @tc.expected: step4. got notification again.
     */
    errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 2);
    }
}

/**
 * @tc.name: SubscribeWithUnsusbscribe002
 * @tc.desc: subscribe events and then unsubscribe all
 * @tc.type: FUNC
 */
HWTEST_F(EventSubscribeTest, SubscribeWithUnsusbscribe002, TestSize.Level2)
{
    auto callback = std::make_shared<ProfileEventCallback>();

    /**
     * @tc.steps: step1. subscribe sync and change event
     */
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    if (MockSubscribeEvents(callback, serviceIds, "") != ERR_OK) {
        DTEST_LOG << "subscribe failed" << std::endl;
        return;
    }

    /**
     * @tc.steps: step2. put service profile which is subscribed
     * @tc.expected: step2. got one notification.
     */
    int32_t errCode = PutFakeSystem();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }

    /**
     * @tc.steps: step3. unsubscribe all events
     */
    if (MockUnsubscribeEvents(callback) != ERR_OK) {
        DTEST_LOG << "unsubscribe failed" << std::endl;
        return;
    }

    /**
     * @tc.steps: step4. put a subscribed service profile
     * @tc.expected: step4. can't receive notification.
     */
    errCode = PutFakeStorage();
    if (errCode == ERR_OK) {
        DTEST_LOG << "put succeeded" << std::endl;
        std::this_thread::sleep_for(1s);
        EXPECT_TRUE(callback->GetNotificationNum() == 1);
    }
}

/**
 * @tc.name: SubDeviceProfile_001
 * @tc.desc: sub device profile
 * @tc.type: FUNC
 * @tc.require: I51HKG
 */
HWTEST_F(EventSubscribeTest, UnsubDeviceProfile_001, TestSize.Level3)
{
    auto callback = std::make_shared<ProfileEventCallback>();
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    std::list<ProfileEvent> failedEvents;
    auto result = DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(
        profileEvents, callback, failedEvents);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_NE(result, ERR_INVALID_DATA);
}
}
}