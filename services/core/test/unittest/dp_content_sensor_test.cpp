/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "collector.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_client.h"
#include "settings_data_manager.h"
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

class CollectorListener : public Collector {
public:
    CollectorListener()
    {
    }
    ~CollectorListener()
    {
    }
    bool ConvertToProfile(DeviceProfile& deviceProfile) override
    {
        return true;
    }
};

/**
 * @tc.name: Collect_001
 * @tc.desc: Collect
 * @tc.type: FUNC
 */
HWTEST_F(DpContentSensorTest, Collect_001, TestSize.Level2)
{
    CollectorListener collector;
    DeviceProfile profile;
    profile.SetDeviceId("test");
    profile.SetDeviceName("test");
    collector.Collect(profile);
    collector.Collect(profile);
    EXPECT_EQ(profile.deviceName_, "test");
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
 * @tc.name: GetProtType_001
 * @tc.desc: GetProtType
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetProtType_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().protType_ = 1;
    int32_t result = systemInfo.GetProtType();
    EXPECT_EQ(result, 1);
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().protType_ = 0;
}

/**
 * @tc.name: GetDeviceName_001
 * @tc.desc: GetDeviceName
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetDeviceName_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().marketName_ = "deviceName";
    std::string result = systemInfo.GetDeviceName();
    EXPECT_EQ(result, "deviceName");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().marketName_ = "";
}

/**
 * @tc.name: GetProductId_001
 * @tc.desc: GetProductId
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetProductId_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().productId_ = "productId_";
    std::string result = systemInfo.GetProductId();
    EXPECT_EQ(result, "productId_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().productId_ = "";
}

/**
 * @tc.name: GetProductName_001
 * @tc.desc: GetProductName
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetProductName_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().marketName_ = "marketName_";
    std::string result = systemInfo.GetProductName();
    EXPECT_EQ(result, "marketName_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().marketName_ = "";
}

/**
 * @tc.name: GetSn_001
 * @tc.desc: GetSn
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetSn_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().serial_ = "serial_";
    std::string result = systemInfo.GetSn();
    EXPECT_EQ(result, "serial_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().serial_ = "";
}

/**
 * @tc.name: GetDeviceModel_001
 * @tc.desc: GetDeviceModel
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetDeviceModel_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceModel_ = "deviceModel_";
    std::string result = systemInfo.GetDeviceModel();
    EXPECT_EQ(result, "deviceModel_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceModel_ = "";
}

/**
 * @tc.name: GetDevType_001
 * @tc.desc: GetDevType
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetDevType_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceType_ = "deviceType_";
    std::string result = systemInfo.GetDevType();
    EXPECT_EQ(result, "deviceType_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceType_ = "";
}

/**
 * @tc.name: GetDeviceManufacturer_001
 * @tc.desc: GetDeviceManufacturer
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetDeviceManufacturer_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().manufacture_ = "manufacture_";
    std::string result = systemInfo.GetDeviceManufacturer();
    EXPECT_EQ(result, "manufacture_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().manufacture_ = "";
}

/**
 * @tc.name: GetDeviceTypeId_001
 * @tc.desc: GetDeviceTypeId
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetDeviceTypeId_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceTypeId_ = "deviceTypeId_";
    std::string result = systemInfo.GetDeviceTypeId();
    EXPECT_EQ(result, "deviceTypeId_");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().deviceTypeId_ = "";
}

/**
 * @tc.name: GetSubProductId_001
 * @tc.desc: GetSubProductId
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetSubProductId_001, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().backcolor_ = "backcolor_";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_.clear();
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_["backcolor_"] = "123";
    std::string result = systemInfo.GetSubProductId();
    EXPECT_EQ(result, "123");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().backcolor_ = "";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_.clear();
}

/**
 * @tc.name: GetSubProductId_002
 * @tc.desc: GetSubProductId
 * @tc.type: FUNC
 * @tc.require: I52U5M
 */
HWTEST_F(DpContentSensorTest, GetSubProductId_002, TestSize.Level3)
{
    SystemInfoCollector systemInfo;
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().backcolor_ = "backcolor_";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_.clear();
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_["test"] = "123";
    std::string result = systemInfo.GetSubProductId();
    EXPECT_EQ(result, "");
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().backcolor_ = "";
    DistributedDeviceProfile::ContentSensorManagerUtils::GetInstance().subProdIdMap_.clear();
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
}
}
