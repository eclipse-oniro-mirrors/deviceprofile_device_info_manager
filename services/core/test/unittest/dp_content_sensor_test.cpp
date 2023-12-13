/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "distributed_device_profile_client.h"
#include "device_info_collector.h"
#include "storage_info_collector.h"
#include "syscap_info_collector.h"
#include "system_info_collector.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;

class DpContentSensorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DpContentSensorTest::SetUpTestCase()
{
}

void DpContentSensorTest::TearDownTestCase()
{
}

void DpContentSensorTest::SetUp()
{
}

void DpContentSensorTest::TearDown()
{
}

/**
 * @tc.name: GetDeviceName_001
 * @tc.desc: get device name
 * @tc.type: FUNC
 */
HWTEST_F(DpContentSensorTest, GetDeviceName_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetDeviceModel_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetDeviceUdid_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetDevType_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetDeviceManufacturer_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetDeviceSerial_001, TestSize.Level2)
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
HWTEST_F(DpContentSensorTest, GetTotalSize_001, TestSize.Level2)
{
    const char* PATH_DATA = "/data";
    struct statvfs diskInfo;
    int ret = statvfs(PATH_DATA, &diskInfo);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetOsVersion_001
 * @tc.desc: GetOsVersion
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetOsVersion_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    std::string result = systemInfo.GetOsVersion();
    EXPECT_NE(result, "");
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, SyscapInfoCollector_001, TestSize.Level3)
{
    DeviceProfile profile;
    profile.SetDeviceId("test");
    profile.SetDeviceName("test");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfile(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, SyscapInfoCollector_002, TestSize.Level3)
{
    DeviceProfile profile;
    profile.SetDeviceId("");
    profile.SetDeviceName("");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfile(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, SyscapInfoCollector_003, TestSize.Level3)
{
    DeviceProfile profile;
    profile.SetDeviceId("");
    profile.SetDeviceName("test");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfile(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: SyscapInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, SyscapInfoCollector_004, TestSize.Level3)
{
    DeviceProfile profile;
    profile.SetDeviceId("test");
    profile.SetDeviceName("");
    SyscapInfoCollector syscapInfo;
    bool result = syscapInfo.ConvertToProfile(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: StorageInfoCollector_001
 * @tc.desc: syscap info collector
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, StorageInfoCollector_001, TestSize.Level3)
{
    DeviceProfile profile;
    profile.SetDeviceId("test");
    profile.SetDeviceName("");
    StorageInfoCollector storageInfo;
    bool result = storageInfo.ConvertToProfile(profile);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetTotalSize_002
 * @tc.desc: get total size
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(DpContentSensorTest, GetTotalSize_002, TestSize.Level3)
{
    StorageInfoCollector storageInfo;
    int64_t result = storageInfo.GetTotalSize();
    EXPECT_NE(result, 0);
}
}
}
