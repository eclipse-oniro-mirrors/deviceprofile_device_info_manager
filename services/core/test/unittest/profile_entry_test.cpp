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

class ProfileEntryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileEntryTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileEntryTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileEntryTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileEntryTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: Marshalling_001
 * @tc.desc: Marshalling of profile entry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEntryTest, Marshalling_001, TestSize.Level3)
{
    Parcel parcel;
    std::shared_ptr<ProfileEntry> temp = std::make_shared<ProfileEntry>();
    bool result = temp->Marshalling(parcel);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: Unmarshalling of profile entry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEntryTest, Unmarshalling_001, TestSize.Level3)
{
    Parcel parcel;
    std::shared_ptr<ProfileEntry> temp = std::make_shared<ProfileEntry>();
    bool result = temp->Unmarshalling(parcel);
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: Unmarshalling of profile entry
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEntryTest, Unmarshalling_002, TestSize.Level3)
{
    Parcel parcel;
    std::shared_ptr<ProfileEntry> temp = std::make_shared<ProfileEntry>();
    bool result = temp->Marshalling(parcel);
    EXPECT_EQ(true, result);
    result = temp->Unmarshalling(parcel);
    EXPECT_EQ(true, result);
}
}
}