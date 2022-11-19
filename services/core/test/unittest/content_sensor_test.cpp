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

#include "app_info_collector.h"
#include "utils.h"

#define private public
#define protected public
#include "content_sensor_manager.h"
#include "device_info_collector.h"
#include "storage_info_collector.h"
#include "syscap_info_collector.h"
#include "system_info_collector.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;
namespace {
constexpr int32_t OHOS_TYPE = 10;
}


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
    EXPECT_NE(result, "");
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
    EXPECT_NE(result, "");
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
    EXPECT_NE(result, "");
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
    EXPECT_NE(result, "");
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
    EXPECT_NE(result, "");
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
    EXPECT_NE(result, "");
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
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetDmsVersion_001
 * @tc.desc: get dms version
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(ContentSensorTest, GetDmsVersion_001, TestSize.Level2)
{
    AppInfoCollector appInfoCollector;
    ServiceCharacteristicProfile profile;
    bool result = appInfoCollector.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetOsType_001
 * @tc.desc: GetOsType
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(ContentSensorTest, GetOsType_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    int32_t result = systemInfo.GetOsType();
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(result, OHOS_TYPE);
}

/**
 * @tc.name: GetOsVersion_001
 * @tc.desc: GetOsVersion
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(ContentSensorTest, GetOsVersion_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    std::string result = systemInfo.GetOsVersion();
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_NE(result, "");
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, SyscapInfoCollector_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, SyscapInfoCollector_002, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, SyscapInfoCollector_003, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("test");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, SyscapInfoCollector_004, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: StorageInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, StorageInfoCollector_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("");
    StorageInfoCollector storageInfo;
    bool result = storageInfo.ConvertToProfileData(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetTotalSize_002
 * @tc.desc: get total size
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ContentSensorTest, GetTotalSize_002, TestSize.Level3)
{
    StorageInfoCollector storageInfo;
    int64_t result = storageInfo.GetTotalSize();
    EXPECT_NE(result, 0);
}
}
}
