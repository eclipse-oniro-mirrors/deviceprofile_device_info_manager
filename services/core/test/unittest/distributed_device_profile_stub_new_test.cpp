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
    int32_t DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile) override;
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& charProfile) override;
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName, bool isMultiUser = false,
        int32_t userId = DEFAULT_USER_ID) override;
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID) override;
    int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IRemoteObject> dpInitedCallback) override;
    int32_t UnSubscribeDeviceProfileInited(int32_t saId) override;
    int32_t SubscribePinCodeInvalid(const std::string& tokenId, sptr<IRemoteObject> pinCodeCallback) override;
    int32_t UnSubscribePinCodeInvalid(const std::string& tokenId) override;
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos) override;
    int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;
    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options,
        std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos) override;
    int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t PutServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile) override;
    int32_t DeleteServiceInfoProfile(const ServiceInfoUniqueKey& key) override;
    int32_t UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile) override;
    int32_t GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
        ServiceInfoProfile& serviceInfoProfile) override;
    int32_t GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    int32_t GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    void DelayUnloadTask() override;
    bool IsInited() override;
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

int32_t MockDistributedDeviceProfileStubNew::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    (void)deviceProfiles;
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
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    (void)deviceId;
    (void)serviceName;
    (void)isMultiUser;
    (void)userId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, bool isMultiUser, int32_t userId)
{
    (void)deviceId;
    (void)serviceName;
    (void)characteristicId;
    (void)isMultiUser;
    (void)userId;
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
int32_t MockDistributedDeviceProfileStubNew::SubscribeDeviceProfileInited(int32_t saId,
    sptr<IRemoteObject> dpInitedCallback)
{
    (void)saId;
    (void)dpInitedCallback;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::UnSubscribeDeviceProfileInited(int32_t saId)
{
    (void)saId;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::SubscribePinCodeInvalid(const std::string& tokenId,
    sptr <IRemoteObject> pinCodeCallback)
{
    (void)tokenId;
    (void)pinCodeCallback;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::UnSubscribePinCodeInvalid(const std::string& tokenId)
{
    (void)tokenId;
    return 0;
}
    
int32_t MockDistributedDeviceProfileStubNew::PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos)
{
    (void)deviceInfos;
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
void MockDistributedDeviceProfileStubNew::DelayUnloadTask()
{
    return;
}
bool MockDistributedDeviceProfileStubNew::IsInited()
{
    return true;
}

int32_t MockDistributedDeviceProfileStubNew::GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles)
{
    (void)options;
    (void)deviceProfiles;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    (void)deviceProfiles;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    (void)productInfos;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    (void)deviceIconInfos;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    (void)filterOptions;
    (void)deviceIconInfos;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::PutServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    (void)serviceInfoProfile;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::DeleteServiceInfoProfile(const ServiceInfoUniqueKey& key)
{
    (void)key;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    (void)serviceInfoProfile;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
    ServiceInfoProfile& serviceInfoProfile)
{
    (void)key;
    (void)serviceInfoProfile;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    (void)key;
    (void)serviceInfoProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetAllServiceInfoProfileList(
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    (void)serviceInfoProfiles;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    (void)key;
    (void)serviceInfoProfiles;
    return 0;
}
/**
 * @tc.name: IsInterfaceTokenValid001
 * @tc.desc: IsInterfaceTokenValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, IsInterfaceTokenValid_001, TestSize.Level1)
{
    std::shared_ptr<DistributedDeviceProfileStubNew> devProStubNew =
       std::make_shared<MockDistributedDeviceProfileStubNew>();

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
    EXPECT_EQ(DP_INTERFACE_CHECK_FAILED, ret);
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

/**
 * @tc.name: NotifyAclEventInner_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_001, TestSize.Level0)
{
    uint32_t code = 1000;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(305, ret);
}

/**
 * @tc.name: NotifyAclEventInner_002
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_002, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_003
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_003, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_004
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_004, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyAclEventInner_005
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_005, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_006
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_006, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_007
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_007, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_WRITE_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_008
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_008, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyAclEventInner_009
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_009, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_010
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_010, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_011
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_011, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_012
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_012, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_013
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_013, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_014
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_014, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyAclEventInner_015
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyAclEventInner_015, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyAclEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyEventInner_001
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_001, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyEventInner_002
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_002, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyEventInner_003
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_003, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyEventInner_004
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_004, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyEventInner_005
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_005, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: NotifyEventInner_006
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_006, TestSize.Level0)
{
    uint32_t code = static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}

/**
 * @tc.name: NotifyEventInner_007
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, NotifyEventInner_007, TestSize.Level0)
{
    uint32_t code = 1000;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = ProfileStub_->NotifyEventInner(code, data, reply, option);
    EXPECT_EQ(305, ret);
}

/**
 * @tc.name: PutAllTrustedDevicesInner001
 * @tc.desc: PutAllTrustedDevicesInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileStubNewTest, PutAllTrustedDevicesInner_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = ProfileStub_->PutAllTrustedDevicesInner(data, reply);
    EXPECT_EQ(DP_READ_PARCEL_FAIL, ret);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
