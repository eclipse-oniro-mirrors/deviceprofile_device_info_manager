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

#include "subscribe_info.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class SubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SubscribeInfoTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void SubscribeInfoTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void SubscribeInfoTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void SubscribeInfoTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoTest, Unmarshalling_001, TestSize.Level3)
{
    Parcel parcel;
    SubscribeInfo subInfo;
    bool result = subInfo.Unmarshalling(parcel);
    EXPECT_NE(true, result);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoTest, Unmarshalling_002, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(1);
    parcel.WriteString("test");
    SubscribeInfo subInfo;
    bool result = subInfo.Unmarshalling(parcel);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoTest, Unmarshalling_003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(1);
    std::string test = R"(
        {"key": "value"}
    )";
    parcel.WriteString(test);
    SubscribeInfo subInfo;
    bool result = subInfo.Unmarshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: operator_001
 * @tc.desc: operator
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SubscribeInfoTest, operator_001, TestSize.Level3)
{
    SubscribeInfo rhs;
    SubscribeInfo subInfo;
    bool result = subInfo.operator != (rhs);
    EXPECT_NE(true, result);
}
}
}