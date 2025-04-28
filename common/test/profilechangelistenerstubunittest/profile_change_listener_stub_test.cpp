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

#include "profile_change_listener_stub_test.h"

#include "ipc_types.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
void ProfileChangeListenerStubTest::SetUpTestCase()
{
}

void ProfileChangeListenerStubTest::TearDownTestCase()
{
}

void ProfileChangeListenerStubTest::SetUp()
{
    listenerStub_ = std::make_shared<MockProfileChangeListenerStub>();
}

void ProfileChangeListenerStubTest::TearDown()
{
    listenerStub_ = nullptr;
}

int32_t MockProfileChangeListenerStub::OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile,
    const TrustDeviceProfile& newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnTrustDeviceProfileActive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnDeviceProfileAdd(const DeviceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnDeviceProfileDelete(const DeviceProfile& profile)
{
    (void)profile;
    return 0;
}


int32_t MockProfileChangeListenerStub::OnDeviceProfileUpdate(const DeviceProfile& oldProfile,
    const DeviceProfile& newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnServiceProfileAdd(const ServiceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnServiceProfileDelete(const ServiceProfile& profile)
{
    (void)profile;
    return 0;
}

int32_t MockProfileChangeListenerStub::OnServiceProfileUpdate(const ServiceProfile& oldProfile,
    const ServiceProfile& newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return 0;
}
int32_t MockProfileChangeListenerStub::OnCharacteristicProfileAdd(const CharacteristicProfile& profile)
{
    (void)profile;
    return 0;
}
int32_t MockProfileChangeListenerStub::OnCharacteristicProfileDelete(const CharacteristicProfile& profile)
{
    (void)profile;
    return 0;
}
int32_t MockProfileChangeListenerStub::OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
    const CharacteristicProfile& newProfile)
{
    (void)oldProfile;
    (void)newProfile;
    return 0;
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_001, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DP_INTERFACE_CHECK_FAILED, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileAddInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnTrustDeviceProfileAddInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileDeleteInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnTrustDeviceProfileDeleteInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileInactiveInner_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileInactiveInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileActive_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileActiveInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileUpdateInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnTrustDeviceProfileUpdateInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnDeviceProfileAddInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnDeviceProfileAddInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnDeviceProfileDeleteInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnDeviceProfileDeleteInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnDeviceProfileUpdateInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnDeviceProfileUpdateInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnServiceProfileAddInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnServiceProfileAddInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnServiceProfileDeleteInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnServiceProfileDeleteInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnServiceProfileUpdateInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnServiceProfileUpdateInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnCharacteristicProfileAddInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnCharacteristicProfileAddInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnCharacteristicProfileDeleteInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnCharacteristicProfileDeleteInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnCharacteristicProfileUpdateInner_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NE(listenerStub_, nullptr);
    int32_t ret = listenerStub_->OnCharacteristicProfileUpdateInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}


HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_002, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_003, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_DELETE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_004, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_UPDATE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_005, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_ADD);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_006, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_DELETE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_007, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_UPDATE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_008, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_ADD);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_009, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_DELETE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_010, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_UPDATE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_011, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_ADD);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_012, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_DELETE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_013, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_UPDATE);
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnRemoteRequest_014, TestSize.Level0)
{
    uint32_t code = 1000;
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    int32_t ret = listenerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(305, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileActiveInner_001, TestSize.Level0)
{
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileActiveInner(data, reply);
    EXPECT_NE(DP_SUCCESS, ret);
}


HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileInactiveInner_001, TestSize.Level0)
{
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileInactiveInner(data, reply);
    EXPECT_NE(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileActive_001, TestSize.Level0)
{
    TrustDeviceProfile profile;
    int32_t ret = listenerStub_->ProfileChangeListenerStub::OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileInactivet_001, TestSize.Level0)
{
    TrustDeviceProfile profile;
    int32_t ret = listenerStub_->ProfileChangeListenerStub::OnTrustDeviceProfileInactive(profile);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileActiveInner_003, TestSize.Level0)
{
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileActiveInner(data, reply);
    EXPECT_NE(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileInactiveInner_003, TestSize.Level0)
{
    MessageParcel data;
    data.WriteInterfaceToken(IProfileChangeListener::GetDescriptor());
    MessageParcel reply;
    int32_t ret = listenerStub_->OnTrustDeviceProfileInactiveInner(data, reply);
    EXPECT_NE(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileActive_003, TestSize.Level0)
{
    TrustDeviceProfile profile;
    int32_t ret = listenerStub_->OnTrustDeviceProfileActive(profile);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileChangeListenerStubTest, OnTrustDeviceProfileInactive_003, TestSize.Level0)
{
    TrustDeviceProfile profile;
    int32_t ret = listenerStub_->OnTrustDeviceProfileInactive(profile);
    EXPECT_EQ(DP_SUCCESS, ret);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
