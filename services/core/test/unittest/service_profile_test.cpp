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

#include "service_characteristic_profile.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ServiceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ServiceProfileTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ServiceProfileTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ServiceProfileTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ServiceProfileTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: SetServiceProfileJson_001
 * @tc.desc: set service profile json
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ServiceProfileTest, SetServiceProfileJson_001, TestSize.Level3)
{
    std::string profileJson;
    ServiceCharacteristicProfile profile;
    profile.SetServiceProfileJson(profileJson);
    EXPECT_EQ("", profileJson);
}

/**
 * @tc.name: GetServiceProfileJson_001
 * @tc.desc: get service profile json
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ServiceProfileTest, GetServiceProfileJson_001, TestSize.Level3)
{
    std::string profileJson = "";
    ServiceCharacteristicProfile profile;
    std::string result = profile.GetServiceProfileJson();
    EXPECT_EQ(profileJson, result);
}

/**
 * @tc.name: Marshalling_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ServiceProfileTest, Marshalling_001, TestSize.Level3)
{
    Parcel parcel;
    ServiceCharacteristicProfile profile;
    bool result = profile.Marshalling(parcel);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ServiceProfileTest, Unmarshalling_001, TestSize.Level3)
{
    Parcel parcel;
    ServiceCharacteristicProfile profile;
    bool result = profile.Unmarshalling(parcel);
    EXPECT_NE(true, result);
}
}
}