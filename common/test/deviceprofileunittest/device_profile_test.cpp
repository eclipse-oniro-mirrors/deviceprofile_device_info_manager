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

#include "device_profile.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceProfileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceProfileTest::SetUpTestCase()
{
}

void DeviceProfileTest::TearDownTestCase()
{
}

void DeviceProfileTest::SetUp()
{
}

void DeviceProfileTest::TearDown()
{
}

HWTEST_F(DeviceProfileTest, Marshalling_001, TestSize.Level0)
{
    DeviceProfile deviceProfile;
    MessageParcel parcel;
    auto result = deviceProfile.Marshalling(parcel);
    EXPECT_EQ(true, result);
}

HWTEST_F(DeviceProfileTest, UnMarshalling_001, TestSize.Level0)
{
    DeviceProfile deviceProfile;
    MessageParcel parcel;
    auto result = deviceProfile.UnMarshalling(parcel);
    EXPECT_EQ(false, result);
}

HWTEST_F(DeviceProfileTest, dump_001, TestSize.Level0)
{
    DeviceProfile deviceProfile;
    auto result = deviceProfile.dump();
    EXPECT_NE(0, result.length());
}
}
}