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

#include "profile_change_notification.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileChangeNotificationTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
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
 * @tc.name: GetDeviceId_001
 * @tc.desc: get device id
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileChangeNotificationTest, GetDeviceId_001, TestSize.Level3)
{
    auto temp = new ProfileChangeNotification();
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
    auto temp = new ProfileChangeNotification();
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
    auto temp = new ProfileChangeNotification();
    bool result = temp->Marshalling(parcel);
    EXPECT_EQ(true, result);
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
    auto temp = new ProfileChangeNotification();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_EQ(false, result);
}
}
}