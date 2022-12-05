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

#include "profile_event_handler_factory.h"
#include "subscribe_info.h"
#include "subscribe_info_checker.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class SubscribeInfoCheckerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SubscribeInfoCheckerTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void SubscribeInfoCheckerTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void SubscribeInfoCheckerTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void SubscribeInfoCheckerTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: Check_001
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_001, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", "1111"}
    };
    subInfo.profileEvent = ProfileEvent::EVENT_UNKNOWN;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Check_002
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_002, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", ""},
        {"serviceIds", "1111"}
    };
    subInfo.profileEvent = ProfileEvent::EVENT_SYNC_COMPLETED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: Check_004
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_004, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", "1"},
        {"serviceIds", "1111"}
    };
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Check_005
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_005, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", 1},
        {"serviceIds", "1111"}
    };
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Check_006
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_006, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", "deviceId"}
    };
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Check_007
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_007, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo = {
        {"deviceId", "deviceId"}
    };
    std::list<std::string> serviceIds = {"fakeStorage", "fakeSystem"};
    subInfo.extraInfo["serviceIds"] = serviceIds;
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: Check_007
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_008, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo["serviceIds"] = nullptr;
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: Check_007
 * @tc.desc: Check
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, Check_009, TestSize.Level3)
{
    SubscribeInfo subInfo;
    subInfo.extraInfo["deviceId"] = nullptr;
    subInfo.profileEvent = ProfileEvent::EVENT_PROFILE_CHANGED;
    std::list<SubscribeInfo> infos(1, subInfo);
    bool ret = SubscribeInfoChecker::GetInstance().Check(infos);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetHandler_001
 * @tc.desc: GetHandler
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoCheckerTest, GetHandler_001, TestSize.Level3)
{
    auto result = ProfileEventHandlerFactory::GetInstance().GetHandler(ProfileEvent::EVENT_PROFILE_END);
    DTEST_LOG << "result: " << result << std::endl;
    EXPECT_EQ(nullptr, result);
}
}
}