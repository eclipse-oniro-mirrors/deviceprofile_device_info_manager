/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <iostream>

#include "profile_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_stub_new.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class MockDistributedDeviceProfileStubNew : public DistributedDeviceProfileStubNew {
    int32_t PutAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t UpdateAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile) override;
    int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles) override;
    int32_t GetAccessControlProfile(std::map<std::string, std::string> queryParams,
        std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t DeleteAccessControlProfile(int32_t accessControlId) override;
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile) override;
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles) override;
    int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile) override;
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles) override;
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile) override;
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile) override;
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& charProfile) override;
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName) override;
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId) override;
    int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;
};

class DistributedDeviceProfileStubNewTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<DistributedDeviceProfileStubNew> ProfileStub_ = nullptr;
};

void DistributedDeviceProfileStubNewTest::SetUpTestCase(void)
{
}

void DistributedDeviceProfileStubNewTest::TearDownTestCase(void)
{
}

void DistributedDeviceProfileStubNewTest::SetUp()
{
    ProfileStub_ = std::make_shared<MockDistributedDeviceProfileStubNew>();
}

void DistributedDeviceProfileStubNewTest::TearDown()
{
    ProfileStub_ = nullptr;
}

int32_t MockDistributedDeviceProfileStubNew::PutAccessControlProfile(const AccessControlProfile& aclProfile)
{
    (void)aclProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::UpdateAccessControlProfile(const AccessControlProfile& aclProfile)
{
    (void)aclProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    (void)deviceId;
    (void)trustDeviceProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    (void)trustDeviceProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    (void)queryParams;
    (void)accessControlProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    (void)accessControlProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteAccessControlProfile(int32_t accessControlId)
{
    (void)accessControlId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    (void)serviceProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    (void)serviceProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    (void)charProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    (void)charProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetDeviceProfile(const std::string& deviceId,
    DeviceProfile& deviceProfile)
{
    (void)deviceId;
    (void)deviceProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetServiceProfile(const std::string& deviceId,
    const std::string& serviceName, ServiceProfile& serviceProfile)
{
    (void)deviceId;
    (void)serviceName;
    (void)serviceProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, CharacteristicProfile& charProfile)
{
    (void)deviceId;
    (void)serviceName;
    (void)characteristicId;
    (void)charProfile;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName)
{
    (void)deviceId;
    (void)serviceName;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId)
{
    (void)deviceId;
    (void)serviceName;
    (void)characteristicId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    (void)subscribeInfo;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    (void)subscribeInfo;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::SyncDeviceProfile(
    const DistributedDeviceProfile::DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    (void)syncOptions;
    (void)syncCompletedCallback;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap)
{
    (void)listenerMap;
    return 0;
}

/**
 * @tc.name: DistributedDeviceProfileStubNew001
 * @tc.desc: DistributedDeviceProfileStubNew
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, DistributedDeviceProfileStubNew_001, TestSize.Level1)
{
    std::shared_ptr<DistributedDeviceProfileStubNew> devProStubNew =
       std::make_shared<MockDistributedDeviceProfileStubNew>();
}

/**
 * @tc.name: IsInterfaceTokenValid001
 * @tc.desc: IsInterfaceTokenValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, IsInterfaceTokenValid_001, TestSize.Level1)
{
    MessageParcel data;
    bool ret = ProfileStub_->IsInterfaceTokenValid(data);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, OnRemoteRequest_001, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, OnRemoteRequest_002, TestSize.Level1)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DP_INTERFACE_CHECK_FAILED, ret);
}

/**
 * @tc.name: PutAccessControlProfileInner001
 * @tc.desc: PutAccessControlProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, PutAccessControlProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->PutAccessControlProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: UpdateAccessControlProfileInner001
 * @tc.desc: UpdateAccessControlProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, UpdateAccessControlProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->UpdateAccessControlProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: GetTrustDeviceProfileInner001
 * @tc.desc: GetTrustDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetTrustDeviceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetTrustDeviceProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: GetAllTrustDeviceProfileInner001
 * @tc.desc: GetAllTrustDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetAllTrustDeviceProfileInner_001, TestSize.Level1)
{
    std::string udid = "udid";
    std::string serviceId = "serviceId";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(udid);
    data.WriteString(serviceId);
    int32_t ret = ProfileStub_->GetAllTrustDeviceProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: GetAccessControlProfileInner001
 * @tc.desc: GetAccessControlProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetAccessControlProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetAccessControlProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: GetAllAccessControlProfileInner001
 * @tc.desc: GetAllAccessControlProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetAllAccessControlProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetAllAccessControlProfileInner(data, reply);
    EXPECT_EQ(DP_WRITE_PARCEL_FAIL, ret);
}

/**
 * @tc.name: DeleteAccessControlProfileInner001
 * @tc.desc: DeleteAccessControlProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, DeleteAccessControlProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->DeleteAccessControlProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: PutServiceProfileInner001
 * @tc.desc: PutServiceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, PutServiceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->PutServiceProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: PutServiceProfileBatchInner001
 * @tc.desc: PutServiceProfileBatchInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, PutServiceProfileBatchInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->PutServiceProfileBatchInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: PutCharacteristicProfileBatchInner001
 * @tc.desc: PutCharacteristicProfileBatchInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, PutCharacteristicProfileBatchInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->PutCharacteristicProfileBatchInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: GetDeviceProfileInner001
 * @tc.desc: GetDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetDeviceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetDeviceProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: GetServiceProfileInner001
 * @tc.desc: GetServiceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetServiceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetServiceProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: GetCharacteristicProfileInner001
 * @tc.desc: GetCharacteristicProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, GetCharacteristicProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->GetCharacteristicProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: DeleteServiceProfileInner001
 * @tc.desc: DeleteServiceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, DeleteServiceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->DeleteServiceProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: DeleteCharacteristicProfileInner001
 * @tc.desc: DeleteCharacteristicProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, DeleteCharacteristicProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->DeleteServiceProfileInner(data, reply);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: SubscribeDeviceProfileInner001
 * @tc.desc: SubscribeDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, SubscribeDeviceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->SubscribeDeviceProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: UnSubscribeDeviceProfileInner001
 * @tc.desc: UnSubscribeDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, UnSubscribeDeviceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->UnSubscribeDeviceProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: SyncDeviceProfileInner001
 * @tc.desc: SyncDeviceProfileInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, SyncDeviceProfileInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->SyncDeviceProfileInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: SendSubscribeInfosInner001
 * @tc.desc: SendSubscribeInfosInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, SendSubscribeInfosInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->SendSubscribeInfosInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
