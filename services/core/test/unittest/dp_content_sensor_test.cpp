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
#include "collector.h"
#include "distributed_device_profile_client.h"
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
}
}
