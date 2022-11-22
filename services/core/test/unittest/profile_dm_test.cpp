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

#include "utils.h"

#define private public
#define protected public
#include "dp_device_manager.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileDmTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileDmTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileDmTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileDmTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileDmTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: WaitForDnetworkReady_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, WaitForDnetworkReady_001, TestSize.Level3)
{
    bool res = DpDeviceManager::GetInstance().WaitForDnetworkReady();
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: GetUdidByNetworkId_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, GetUdidByNetworkId_001, TestSize.Level3)
{
    std::string udid;
    bool res = DpDeviceManager::GetInstance().GetUdidByNetworkId("", udid);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GetUuidByNetworkId_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, GetUuidByNetworkId_001, TestSize.Level3)
{
    std::string uuid;
    DpDeviceManager::GetInstance().AddLocalDeviceIds();
    DpDeviceManager::GetInstance().RecoverDevicesIfNeeded();
    bool res = DpDeviceManager::GetInstance().GetUuidByNetworkId("", uuid);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: TransformDeviceId
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, TransformDeviceId_001, TestSize.Level3)
{
    std::string queryUdid;
    std::string udid;
    DpDeviceManager::GetInstance().RemoveDeviceIds("");
    DpDeviceManager::GetInstance().GetLocalDeviceUdid(udid);
    DpDeviceManager::GetInstance().RemoveDeviceIdsByUdid("");
    DpDeviceManager::GetInstance().RemoveExpiredDeviceIds("");
    bool res = DpDeviceManager::GetInstance().TransformDeviceId("", queryUdid, DeviceIdType::UUID);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: Init_001
 * @tc.desc: set service profile json
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, Init_001, TestSize.Level3)
{
    bool res = DpDeviceManager::GetInstance().Init();
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: WaitForDnetworkReady_002
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, WaitForDnetworkReady_002, TestSize.Level3)
{
    bool res = DpDeviceManager::GetInstance().WaitForDnetworkReady();
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: ConnectDeviceManager_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, ConnectDeviceManager_001, TestSize.Level3)
{
    bool res = DpDeviceManager::GetInstance().ConnectDeviceManager();
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: GetUdidByNetworkId_002
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, GetUdidByNetworkId_002, TestSize.Level3)
{
    auto dpDeviceInfo = std::make_shared<DeviceInfo>(
        "12345678", "12345678", 0x00);
    DpDeviceManager::GetInstance().OnNodeOnline(dpDeviceInfo);
    std::string udid;
    bool res = DpDeviceManager::GetInstance().GetUdidByNetworkId("", udid);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: GetUuidByNetworkId_002
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, GetUuidByNetworkId_002, TestSize.Level3)
{
    std::string uuid;
    DpDeviceManager::GetInstance().OnNodeOffline("");
    DpDeviceManager::GetInstance().AddLocalDeviceIds();
    DpDeviceManager::GetInstance().RecoverDevicesIfNeeded();
    bool res = DpDeviceManager::GetInstance().GetUuidByNetworkId("", uuid);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: TransformDeviceId_002
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, TransformDeviceId_002, TestSize.Level3)
{
    std::string queryUdid;
    std::string udid;
    DpDeviceManager::GetInstance().RemoveDeviceIds("");
    DpDeviceManager::GetInstance().GetLocalDeviceUdid(udid);
    DpDeviceManager::GetInstance().RemoveDeviceIdsByUdid("");
    DpDeviceManager::GetInstance().RemoveExpiredDeviceIds("");
    std::list<std::string> deviceIdList;
    deviceIdList.emplace_back("testttt");
    DpDeviceManager::GetInstance().GetDeviceIdList(deviceIdList);
    std::shared_ptr<DeviceInfo> device;
    std::list<std::shared_ptr<DeviceInfo>> deviceList;
    DpDeviceManager::GetInstance().GetDeviceList(deviceList);
    bool res = DpDeviceManager::GetInstance().TransformDeviceId("", queryUdid, DeviceIdType::UUID);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: DisconnectDeviceManager_001
 * @tc.desc: marshalling
 * @tc.type: FUNC
 * @tc.require: I4OH94
 */
HWTEST_F(ProfileDmTest, DisconnectDeviceManager_001, TestSize.Level3)
{
    std::string queryUdid;
    std::string udid;
    std::list<std::string> deviceIdList;
    std::map<std::string, std::shared_ptr<DeviceInfo>> remoteDeviceInfoMap_;
    std::shared_ptr<DeviceInfo> deviceInfo = std::make_shared<DeviceInfo>("test", "test", 1);
    DpDeviceManager::GetInstance().remoteDeviceInfoMap_["testttt"] = deviceInfo;
    deviceIdList.emplace_back("testttt");
    DpDeviceManager::GetInstance().GetDeviceIdList(deviceIdList);
    std::shared_ptr<DeviceInfo> device;
    std::list<std::shared_ptr<DeviceInfo>> deviceList;
    DpDeviceManager::GetInstance().GetDeviceList(deviceList);
    bool res = DpDeviceManager::GetInstance().DisconnectDeviceManager();
    EXPECT_EQ(true, res);
}
}
}