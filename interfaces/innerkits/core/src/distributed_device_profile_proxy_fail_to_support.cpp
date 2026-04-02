/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_proxy.h"

#include <string>

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "ProxyFailToSupport";
constexpr int32_t DP_NOT_SUPPORT = 801;
}

int32_t DistributedDeviceProfileProxy::PutAccessControlProfile(const AccessControlProfile& aclProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UpdateAccessControlProfile(const AccessControlProfile& aclProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetTrustDeviceProfile(
    const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetAccessControlProfile(
    std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetAllAclIncludeLnnAcl(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteAccessControlProfile(int32_t accessControlId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutSessionKey(
    uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetSessionKey(
    uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UpdateSessionKey(
    uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutServiceProfileBatch(
    const std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetDeviceProfile(
    const std::string& deviceId, DeviceProfile& deviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetDeviceProfiles(
    DeviceProfileFilterOptions& options, std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceProfile(
    const std::string& deviceId, const std::string& serviceName, ServiceProfile& serviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, CharacteristicProfile& charProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteServiceProfile(
    const std::string& deviceId, const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, bool isMultiUser, int32_t userId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SubscribeDeviceProfileInited(
    int32_t saId, sptr<IRemoteObject> dpInitedCallback)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UnSubscribeDeviceProfileInited(int32_t saId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SubscribePinCodeInvalid(
    const std::string& bundleName, int32_t pinExchangeType, sptr<IRemoteObject> pinCodeCallback)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UnSubscribePinCodeInvalid(
    const std::string& bundleName, int32_t pinExchangeType)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SyncDeviceProfile(
    const DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SyncStaticProfile(
    const DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::SendSubscribeInfos(
    std::map<std::string, SubscribeInfo> listenerMap)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutAllTrustedDevices(
    const std::vector<TrustedDeviceInfo> deviceInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutDeviceIconInfoBatch(
    const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetDeviceIconInfos(
    const DeviceIconInfoFilterOptions& filterOptions, std::vector<DeviceIconInfo>& deviceIconInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UpdateServiceInfoProfile(
    const ServiceInfoProfile& serviceInfoProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileByUniqueKey(
    const ServiceInfoUniqueKey& key, ServiceInfoProfile& serviceInfoProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileListByTokenId(
    const ServiceInfoUniqueKey& key, std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetAllServiceInfoProfileList(
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileListByBundleName(
    const ServiceInfoUniqueKey& key, std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetLocalServiceInfoByBundleAndPinType(
    const std::string& bundleName, int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteLocalServiceInfo(
    const std::string& bundleName, int32_t pinExchangeType)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::RegisterBusinessCallback(
    const std::string& saId, const std::string& businessKey, sptr<IRemoteObject> businessCallback)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::UnRegisterBusinessCallback(
    const std::string& saId, const std::string& businessKey)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutBusinessEvent(const BusinessEvent& event)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetBusinessEvent(BusinessEvent& event)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::PutServiceInfoProfile(
    const ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileByServiceId(
    int64_t serviceId, ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileByTokenId(
    int64_t tokenId, std::vector<ServiceInfoProfileNew>& serviceInfoProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileByRegServiceId(
    int32_t regServiceId, ServiceInfoProfileNew& serviceInfoProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
