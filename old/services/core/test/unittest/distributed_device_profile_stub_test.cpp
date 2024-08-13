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
#include <map>

#include "distributed_device_profile_stub.h"
#include "idistributed_device_profile.h"
#include "iremote_stub.h"
#include "device_profile_errors.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_enums.h"
#include "deviceprofile_ipc_interface_code.h"
#include "distributed_device_profile_errors.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {

using namespace OHOS::DistributedDeviceProfile;
using namespace testing;
using namespace testing::ext;

class DeviceProfileStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceProfileStubTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void DeviceProfileStubTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void DeviceProfileStubTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void DeviceProfileStubTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

class DistributedDeviceProfileStubTest : public DistributedDeviceProfileStub {
public:
    DistributedDeviceProfileStubTest() = default;
    ~DistributedDeviceProfileStubTest() = default;
    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile)
    {
        (void)profile;
        return 0;
    }
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile)
    {
        (void)udid;
        (void)serviceId;
        (void)profile;
        return 0;
    }
    int32_t DeleteDeviceProfile(const std::string& serviceId)
    {
        (void)serviceId;
        return 0;
    }
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)subscribeInfos;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)profileEvents;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions, const sptr<IRemoteObject>& profileEventNotifier)
    {
        (void)syncOptions;
        (void)profileEventNotifier;
        return 0;
    }
};

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::PUT_ACL_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::GET_TRUST_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::GET_ACL_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::GET_ALL_ACL_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_WRITE_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_007, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::DELETE_ACL_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_008, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_009, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_010, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::SEND_SUBSCRIBE_INFOS);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_011, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::PUT_SERVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_012, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_013, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::PUT_CHAR_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_014, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DistributedDeviceProfile::DPInterfaceCode::PUT_CHAR_PROFILE_BATCH);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyAclEventInner_015, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1000;
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(305, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::PUT_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_NULL_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::DELETE_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(0, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::GET_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::SUBSCRIBE_PROFILE_EVENT);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::UNSUBSCRIBE_PROFILE_EVENT);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyOldEventInner_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDeviceProfileInterfaceCode::SYNC_DEVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyOldEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_NULL_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW);
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, result);
}

HWTEST_F(DeviceProfileStubTest, NotifyNewEventInner_007, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = 1000;
    std::shared_ptr<DistributedDeviceProfileStub> distributedDeviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    int32_t result = distributedDeviceProfileStub->NotifyNewEventInner(code, data, reply, option);
    EXPECT_EQ(305, result);
}
} // namespace DeviceProfile
} // namespace OHOS