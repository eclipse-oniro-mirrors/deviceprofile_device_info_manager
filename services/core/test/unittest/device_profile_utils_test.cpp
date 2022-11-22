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

#include "device_profile_dumper.h"
#include "device_profile_utils.h"
#include "sync_options.h"
#include "subscribe_info.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr uint32_t MAX_EVENT_LEN = 1000001;
constexpr int32_t MAX_DEVICE_LEN = 1000001;
}

class DeviceProfileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceProfileUtilsTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void DeviceProfileUtilsTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void DeviceProfileUtilsTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void DeviceProfileUtilsTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: WriteProfileEvents_001
 * @tc.desc: WriteProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, WriteProfileEvents_001, TestSize.Level3)
{
    std::list<ProfileEvent> failedEvents;
    Parcel parcel;
    bool ret = DeviceProfileUtils::WriteProfileEvents(failedEvents, parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, Unmarshalling_001, TestSize.Level3)
{
    std::list<ProfileEvent> failedEvents;
    failedEvents.emplace_back(ProfileEvent::EVENT_PROFILE_CHANGED);
    failedEvents.emplace_back(ProfileEvent::EVENT_SYNC_COMPLETED);
    Parcel parcel;
    bool ret = DeviceProfileUtils::WriteProfileEvents(failedEvents, parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ReadProfileEvents_001
 * @tc.desc: ReadProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, ReadProfileEvents_001, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(MAX_EVENT_LEN);
    std::list<ProfileEvent> failedEvents;
    bool ret = DeviceProfileUtils::ReadProfileEvents(parcel, failedEvents);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ReadProfileEvents_002
 * @tc.desc: ReadProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, ReadProfileEvents_002, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(1);
    parcel.WriteUint32(1);
    std::list<ProfileEvent> failedEvents;
    bool ret = DeviceProfileUtils::ReadProfileEvents(parcel, failedEvents);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ReadProfileEvents_003
 * @tc.desc: ReadProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, ReadProfileEvents_003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(1);
    parcel.WriteUint32(0);
    std::list<ProfileEvent> failedEvents;
    bool ret = DeviceProfileUtils::ReadProfileEvents(parcel, failedEvents);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ReadProfileEvents_003
 * @tc.desc: ReadProfileEvents
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, ReadProfileEvents_004, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteUint32(1);
    parcel.WriteUint32(4);
    std::list<ProfileEvent> failedEvents;
    bool ret = DeviceProfileUtils::ReadProfileEvents(parcel, failedEvents);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, Dump_001, TestSize.Level3)
{
    std::string result;
    std::vector<std::string> args;
    bool ret = DeviceProfileDumper::Dump(args, result);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Marshalling_001
 * @tc.desc: dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, SyncOptionsMarshalling_001, TestSize.Level3)
{
    SyncOptions syncOption;
    Parcel parcel;
    bool ret = syncOption.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Marshalling_002
 * @tc.desc: dump
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, SyncOptionsMarshalling_002, TestSize.Level3)
{
    SyncOptions syncOption;
    syncOption.AddDevice("1234");
    Parcel parcel;
    bool ret = syncOption.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, SyncOptionsUnmarshalling_001, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    parcel.WriteInt32(0);
    SyncOptions syncOption;
    bool ret = syncOption.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, SyncOptionsUnmarshalling_002, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    parcel.WriteInt32(MAX_DEVICE_LEN);
    SyncOptions syncOption;
    bool ret = syncOption.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Unmarshalling_003
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(DeviceProfileUtilsTest, SyncOptionsUnmarshalling_003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    parcel.WriteInt32(1);
    parcel.WriteString("12345");
    SyncOptions syncOption;
    bool ret = syncOption.Unmarshalling(parcel);
    EXPECT_TRUE(ret);
}
}
}