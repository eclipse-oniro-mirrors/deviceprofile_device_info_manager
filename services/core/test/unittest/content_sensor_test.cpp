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

#include <sys/statvfs.h>

#include "utils.h"

#define private public
#define protected public
#include "device_info_collector.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ContentSensorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ContentSensorTest::SetUpTestCase()
{
}

void ContentSensorTest::TearDownTestCase()
{
}

void ContentSensorTest::SetUp()
{
}

void ContentSensorTest::TearDown()
{
}

/**
 * @tc.name: GetDeviceName_001
 * @tc.desc: get device name
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDeviceName_001, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDeviceName();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetDeviceModel_002
 * @tc.desc: get device model
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDeviceModel_002, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDeviceModel();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetDeviceUdid_003
 * @tc.desc: get device udid
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDeviceUdid_003, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDeviceUdid();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetDevType_004
 * @tc.desc: get device type
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDevType_004, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDevType();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetDeviceManufacturer_001
 * @tc.desc: get device manufacturer
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDeviceManufacturer_001, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDeviceManufacturer();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetDeviceSerial_001
 * @tc.desc: get device serial
 * @tc.type: FUNC
 */
HWTEST_F(ContentSensorTest, GetDeviceSerial_001, TestSize.Level2)
{
    DeviceInfoCollector devInfo;
    auto result = devInfo.GetDeviceSerial();
    EXPECT_TRUE(result != "");
}

/**
 * @tc.name: GetTotalSize_001
 * @tc.desc: get total size
 * @tc.type: FUNC
 * @tc.require: I5J7PW
 */
HWTEST_F(ContentSensorTest, GetTotalSize_001, TestSize.Level2)
{
    const char* PATH_DATA = "/data";
    struct statvfs diskInfo;
    int ret = statvfs(PATH_DATA, &diskInfo);
    EXPECT_TRUE(ret == 0);
}
}
}
