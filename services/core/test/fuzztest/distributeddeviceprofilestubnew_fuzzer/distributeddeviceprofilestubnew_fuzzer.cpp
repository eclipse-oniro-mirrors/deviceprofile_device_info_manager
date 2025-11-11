/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributeddeviceprofilestubnew_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include "sys/stat.h"

#include "distributed_device_profile_stub_new.h"
#include "distributed_device_profile_constants.h"
#include "ipc_skeleton.h"
#include "service_info_profile_new.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::u16string DP_INTERFACE_TOKEN = u"OHOS.DeviceProfile.IDistributedDeviceProfile";
}

class MockDistributedDeviceProfileStubNew : public DistributedDeviceProfileStubNew {
    int32_t PutAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t UpdateAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile) override;
    int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles) override;
    int32_t GetAccessControlProfile(std::map<std::string, std::string> queryParams,
        std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t GetAllAclIncludeLnnAcl(std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t DeleteAccessControlProfile(int32_t accessControlId) override;
    int32_t PutSessionKey(uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId) override;
    int32_t GetSessionKey(uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey) override;
    int32_t UpdateSessionKey(uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey) override;
    int32_t DeleteSessionKey(uint32_t userId, int32_t sessionKeyId) override;
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
    int32_t SubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType,
        sptr<IRemoteObject> pinCodeCallback) override;
    int32_t UnSubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType) override;
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos) override;
    int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SyncStaticProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;
    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options,
        std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos) override;
    int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfo) override;
    int32_t DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId) override;
    int32_t UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile) override;
    int32_t GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
        ServiceInfoProfile& serviceInfoProfile) override;
    int32_t GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    int32_t GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles) override;
    int32_t PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo) override;
    int32_t UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo) override;
    int32_t GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
        int32_t pinExchangeType, LocalServiceInfo& localServiceInfo) override;
    int32_t DeleteLocalServiceInfo(const std::string& bundleName, int32_t pinExchangeType) override;
    int32_t RegisterBusinessCallback(const std::string& saId, const std::string& businessKey,
        sptr<IRemoteObject> businessCallback) override;
    int32_t UnRegisterBusinessCallback(const std::string& saId, const std::string& businessKey) override;
    int32_t PutBusinessEvent(const BusinessEvent& event) override;
    int32_t GetBusinessEvent(BusinessEvent& event) override;
    int32_t GetServiceInfo(ServiceInfoProfileNew& serviceInfo);
    int32_t GetServiceInfoProfileByServiceId(int64_t serviceId,
        ServiceInfoProfileNew& serviceInfoProfile) override;
    int32_t GetServiceInfoProfileByTokenId(int64_t tokenId,
        std::vector<ServiceInfoProfileNew>& serviceInfoProfiles) override;
    int32_t GetServiceInfoProfileByRegServiceId(int32_t regServiceId,
        ServiceInfoProfileNew& serviceInfoProfile) override;

    void DelayUnloadTask() override;
    bool IsInited() override;
};

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
int32_t MockDistributedDeviceProfileStubNew::GetAllAclIncludeLnnAcl(
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
int32_t MockDistributedDeviceProfileStubNew::PutSessionKey(
    uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    (void)userId;
    (void)sessionKey;
    (void)sessionKeyId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetSessionKey(
    uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    (void)userId;
    (void)sessionKey;
    (void)sessionKeyId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::UpdateSessionKey(
    uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    (void)userId;
    (void)sessionKey;
    (void)sessionKeyId;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    (void)userId;
    (void)sessionKeyId;
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

int32_t MockDistributedDeviceProfileStubNew::SubscribePinCodeInvalid(const std::string& bundleName,
    int32_t pinExchangeType, sptr <IRemoteObject> pinCodeCallback)
{
    (void)bundleName;
    (void)pinExchangeType;
    (void)pinCodeCallback;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::UnSubscribePinCodeInvalid(const std::string& bundleName,
    int32_t pinExchangeType)
{
    (void)bundleName;
    (void)pinExchangeType;
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
int32_t MockDistributedDeviceProfileStubNew::SyncStaticProfile(
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

int32_t MockDistributedDeviceProfileStubNew::PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfo)
{
    (void)serviceInfo;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId)
{
    (void)regServiceId;
    (void)userId;
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
int32_t MockDistributedDeviceProfileStubNew::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    (void)localServiceInfo;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    (void)localServiceInfo;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
    int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    (void)bundleName;
    (void)pinExchangeType;
    (void)localServiceInfo;
    return 0;
}
int32_t MockDistributedDeviceProfileStubNew::DeleteLocalServiceInfo(const std::string& bundleName,
    int32_t pinExchangeType)
{
    (void)bundleName;
    (void)pinExchangeType;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::RegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey, sptr<IRemoteObject> businessCallback)
{
    (void)saId;
    (void)businessKey;
    (void)businessCallback;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::UnRegisterBusinessCallback(const std::string& saId,
    const std::string& businessKey)
{
    (void)saId;
    (void)businessKey;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::PutBusinessEvent(const BusinessEvent& event)
{
    (void)event;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetBusinessEvent(BusinessEvent& event)
{
    (void)event;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfo(ServiceInfoProfileNew& serviceInfo)
{
    (void)serviceInfo;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileByServiceId(int64_t serviceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    (void)serviceId;
    (void)serviceInfoProfile;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileByTokenId(int64_t tokenId,
    std::vector<ServiceInfoProfileNew>& serviceInfoProfiles)
{
    (void)tokenId;
    (void)serviceInfoProfiles;
    return 0;
}

int32_t MockDistributedDeviceProfileStubNew::GetServiceInfoProfileByRegServiceId(int32_t regServiceId,
    ServiceInfoProfileNew& serviceInfoProfile)
{
    (void)regServiceId;
    (void)serviceInfoProfile;
    return 0;
}
void PutServiceInfoProfileNewInnerFuzzTest(FuzzedDataProvider &fdp)
{
    MessageParcel data;
    std::string rawdata = fdp.ConsumeRandomLengthString();
    data.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    data.WriteBuffer(&rawdata, rawdata.length());
    data.RewindRead(0);
    MessageParcel reply;

    std::shared_ptr<DistributedDeviceProfileStubNew> ProfileStub_ = nullptr;
    ProfileStub_ = std::make_shared<MockDistributedDeviceProfileStubNew>();
    ProfileStub_->PutServiceInfoProfileInner(data, reply);
    ProfileStub_ = nullptr;
}

void DeleteServiceInfoProfileNewInnerFuzzTest(FuzzedDataProvider &fdp)
{
    std::string rawdata = fdp.ConsumeRandomLengthString();
    MessageParcel mData;
    mData.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    mData.WriteBuffer(&rawdata, rawdata.length());
    mData.RewindRead(0);
    MessageParcel reply;

    std::shared_ptr<DistributedDeviceProfileStubNew> ProfileStub_ = nullptr;
    ProfileStub_ = std::make_shared<MockDistributedDeviceProfileStubNew>();
    ProfileStub_->DeleteServiceInfoProfileInner(mData, reply);
    ProfileStub_ = nullptr;
}

void GetServiceInfoProfileByServiceIdInnerFuzzTest(FuzzedDataProvider &fdp)
{
    std::string rawdata = fdp.ConsumeRandomLengthString();
    MessageParcel mData;
    mData.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    mData.WriteBuffer(&rawdata, rawdata.length());
    mData.RewindRead(0);
    MessageParcel reply;

    std::shared_ptr<DistributedDeviceProfileStubNew> ProfileStub_ = nullptr;
    ProfileStub_ = std::make_shared<MockDistributedDeviceProfileStubNew>();
    ProfileStub_->GetServiceInfoProfileByServiceIdInner(mData, reply);
    ProfileStub_ = nullptr;
}

void GetServiceInfoProfileByTokenIdInnerFuzzTest(FuzzedDataProvider &fdp)
{
    std::string rawdata = fdp.ConsumeRandomLengthString();
    MessageParcel mData;
    mData.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    mData.WriteBuffer(&rawdata, rawdata.length());
    mData.RewindRead(0);
    MessageParcel reply;

    std::shared_ptr<DistributedDeviceProfileStubNew> ProfileStub_ = nullptr;
    ProfileStub_ = std::make_shared<MockDistributedDeviceProfileStubNew>();
    ProfileStub_->GetServiceInfoProfileByTokenIdInner(mData, reply);
    ProfileStub_ = nullptr;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    size_t maxDataSize = sizeof(int64_t) * 2;
    if (!data || size < maxDataSize) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::DistributedDeviceProfile::PutServiceInfoProfileNewInnerFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileNewInnerFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByTokenIdInnerFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByServiceIdInnerFuzzTest(fdp);

    return 0;
}
}
