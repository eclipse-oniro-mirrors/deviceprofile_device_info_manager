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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#include "distributed_device_profile_service_new.h"
#include "multi_user_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "AccountCommonEventTest";
}
class AccountCommonEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountCommonEventTest::SetUpTestCase()
{
}

void AccountCommonEventTest::TearDownTestCase()
{
}

void AccountCommonEventTest::SetUp()
{
}

void AccountCommonEventTest::TearDown()
{
}

/*
 * @tc.name: SubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, SubscribeAccountCommonEvent_001, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventManager->eventValidFlag_ = true;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    bool ret = accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: SubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, SubscribeAccountCommonEvent_002, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventManager->eventValidFlag_ = false;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    bool ret = accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: SubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, SubscribeAccountCommonEvent_003, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    bool ret = accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: SubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, SubscribeAccountCommonEvent_004, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = nullptr;
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    bool ret = accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: SubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, SubscribeAccountCommonEvent_005, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = nullptr;
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventVec.emplace_back("11111");
    bool ret = accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: UnsubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, UnsubscribeAccountCommonEvent_001, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    accountCommonEventManager->eventValidFlag_ = false;
    bool ret = accountCommonEventManager->UnsubscribeAccountCommonEvent();
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: UnsubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, UnsubscribeAccountCommonEvent_002, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
        AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventManager->eventValidFlag_ = false;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    accountCommonEventManager->subscriber_ = nullptr;
    bool ret = accountCommonEventManager->UnsubscribeAccountCommonEvent();
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: UnsubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, UnsubscribeAccountCommonEvent_003, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    accountCommonEventManager->eventValidFlag_ = true;
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    EventFwk::MatchingSkills matchingSkills;
    for (auto &item : accountCommonEventVec) {
        matchingSkills.AddEvent(item);
    }
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    accountCommonEventManager->subscriber_ =
        std::make_shared<DpAccountEventSubscriber>(subscriberInfo, callback, accountCommonEventVec);
    accountCommonEventManager->statusChangeListener_ = nullptr;
    bool ret = accountCommonEventManager->UnsubscribeAccountCommonEvent();
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: UnsubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, UnsubscribeAccountCommonEvent_004, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    accountCommonEventManager->eventValidFlag_ = true;
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    EventFwk::MatchingSkills matchingSkills;
    for (auto &item : accountCommonEventVec) {
        matchingSkills.AddEvent(item);
    }
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    accountCommonEventManager->subscriber_ =
        std::make_shared<DpAccountEventSubscriber>(subscriberInfo, callback, accountCommonEventVec);
    accountCommonEventManager->statusChangeListener_ =
        new (std::nothrow) DpAccountCommonEventManager::
        SystemAbilityStatusChangeListener(accountCommonEventManager->subscriber_);
    bool ret = accountCommonEventManager->UnsubscribeAccountCommonEvent();
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: UnsubscribeAccountCommonEvent
 * @tc.desc: Normal testCase of AccountCommonEventTest for CRUD
 * @tc.type: FUNC
 */
HWTEST_F(AccountCommonEventTest, UnsubscribeAccountCommonEvent_005, TestSize.Level1)
{
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager;
    accountCommonEventManager = std::make_shared<DpAccountCommonEventManager>();
    AccountEventCallback callback = [=](const auto &arg1, const auto &arg2) {
        DistributedDeviceProfileServiceNew::GetInstance().AccountCommonEventCallback(arg1, arg2);
    };
    std::vector<std::string> accountCommonEventVec;
    accountCommonEventManager->eventValidFlag_ = false;
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT);
    accountCommonEventVec.emplace_back(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGIN);
    accountCommonEventManager->SubscribeAccountCommonEvent(accountCommonEventVec, callback);
    bool ret = accountCommonEventManager->UnsubscribeAccountCommonEvent();
    EXPECT_EQ(ret, true);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS