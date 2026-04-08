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

#include "distributed_device_profile_client.h"

#include <string>

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "ClientFailToSupport";
constexpr int32_t DP_NOT_SUPPORT = 801;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileClient);

int32_t DistributedDeviceProfileClient::PutAccessControlProfile(
    const AccessControlProfile& accessControlProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UpdateAccessControlProfile(
    const AccessControlProfile& accessControlProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetTrustDeviceProfile(
    const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetAllTrustDeviceProfile(
    std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetAccessControlProfile(
    std::map<std::string, std::string> params, std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetAllAclIncludeLnnAcl(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteAccessControlProfile(int32_t accessControlId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutSessionKey(
    uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetSessionKey(
    uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UpdateSessionKey(
    uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutServiceProfileBatch(
    const std::vector<ServiceProfile>& serviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfile(
    const CharacteristicProfile& characteristicProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetDeviceProfile(
    const std::string& deviceId, DeviceProfile& deviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetDeviceProfiles(
    DeviceProfileFilterOptions& options, std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetServiceProfile(
    const std::string& deviceId, const std::string& serviceName, ServiceProfile& serviceProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId,
    CharacteristicProfile& characteristicProfile)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteServiceProfile(
    const std::string& deviceId, const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, bool isMultiUser, int32_t userId)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutDeviceIconInfoBatch(
    const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetDeviceIconInfos(
    const DeviceIconInfoFilterOptions& filterOptions, std::vector<DeviceIconInfo>& deviceIconInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    std::lock_guard<std::mutex> lock(subscribeLock_);
    subscribeInfos_.clear();
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    std::lock_guard<std::mutex> lock(subscribeLock_);
    subscribeInfos_.clear();
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SyncDeviceProfile(
    const DpSyncOptions& syncOptions, sptr<ISyncCompletedCallback> syncCb)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SyncStaticProfile(
    const DpSyncOptions& syncOptions, sptr<ISyncCompletedCallback> syncCb)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfileInited(
    int32_t saId, sptr<IDpInitedCallback> initedCb)
{
    std::lock_guard<std::mutex> lock(dpInitedLock_);
    saId_ = saId;
    dpInitedCallback_ = initedCb;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfileInited(int32_t saId)
{
    std::lock_guard<std::mutex> lock(dpInitedLock_);
    saId_ = 0;
    dpInitedCallback_ = nullptr;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SubscribePinCodeInvalid(
    const std::string& bundleName, int32_t pinExchangeType, sptr<IPincodeInvalidCallback> pinCodeCallback)
{
    std::lock_guard<std::mutex> lock(pinCodeLock_);
    bundleName_ = bundleName;
    pinExchangeType_ = pinExchangeType;
    pinCodeCallback_ = pinCodeCallback;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UnSubscribePinCodeInvalid(
    const std::string& bundleName, int32_t pinExchangeType)
{
    std::lock_guard<std::mutex> lock(pinCodeLock_);
    bundleName_.clear();
    pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE;
    pinCodeCallback_ = nullptr;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutAllTrustedDevices(
    const std::vector<TrustedDeviceInfo>& deviceInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetLocalServiceInfoByBundleAndPinType(
    const std::string& bundleName, int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteLocalServiceInfo(
    const std::string& bundleName, int32_t pinExchangeType)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::RegisterBusinessCallback(
    const std::string& saId, const std::string& businessKey, sptr<IBusinessCallback> businessCallback)
{
    std::lock_guard<std::mutex> lock(businessLock_);
    strSaId_ = saId;
    businessKey_ = businessKey;
    businessCallback_ = businessCallback;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::UnRegisterBusinessCallback(
    const std::string& saId, const std::string& businessKey)
{
    std::lock_guard<std::mutex> lock(businessLock_);
    strSaId_.clear();
    businessKey_.clear();
    businessCallback_ = nullptr;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutBusinessEvent(const BusinessEvent& event)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetBusinessEvent(BusinessEvent& event)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::PutServiceInfo(const ServiceInfo& serviceInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::DeleteServiceInfo(const UserInfo& userInfo)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::GetServiceInfosByUserInfo(
    const UserInfo& userInfo, std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

int32_t DistributedDeviceProfileClient::SubscribeAllServiceInfo(
    int32_t saId, sptr<IRemoteObject> listener)
{
    std::lock_guard<std::mutex> lock(serInfolistenerLock_);
    serviceInfoSaId_ = saId;
    serviceInfolistener_ = listener;
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

void DistributedDeviceProfileClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject>& remoteObject)
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
    dpDeathRecipient_ = nullptr;
    loadSystemAbilityFinish_ = true;
    proxyConVar_.notify_all();
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::LoadSystemAbilityFail()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
    loadSystemAbilityFinish_ = false;
    proxyConVar_.notify_all();
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseResource()
{
    ReleaseSubscribeDeviceProfileSA();
    ReleaseSubscribeDeviceProfileInited();
    ReleaseSubscribePinCodeInvalid();
    ReleaseDeathRecipient();
    ReleaseRegisterBusinessCallback();
    ReSubscribeAllServiceInfo();
    (void)retryErrCodes_.size();
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReSubscribeAllServiceInfo()
{
    std::lock_guard<std::mutex> lock(serInfolistenerLock_);
    serviceInfoSaId_ = 0;
    serviceInfolistener_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::SystemAbilityListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::SystemAbilityListener::OnRemoveSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::SendSubscribeInfosToService()
{
    std::lock_guard<std::mutex> lock(subscribeLock_);
    subscribeInfos_.clear();
    HILOGI("%{public}s no-build", __func__);
}

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::LoadDeviceProfileService()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
    loadSystemAbilityFinish_ = false;
    HILOGI("%{public}s no-build", __func__);
    return dpProxy_;
}

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::GetDeviceProfileService()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    HILOGI("%{public}s no-build", __func__);
    return dpProxy_;
}

void DistributedDeviceProfileClient::OnServiceDied(const sptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpProxy_ = nullptr;
    dpDeathRecipient_ = nullptr;
    loadSystemAbilityFinish_ = false;
    proxyConVar_.notify_all();
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::SubscribeDeviceProfileSA()
{
    std::lock_guard<std::mutex> lock(saListenerLock_);
    saListenerCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::StartThreadSendSubscribeInfos()
{
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReSubscribeDeviceProfileInited()
{
    std::lock_guard<std::mutex> lock(dpInitedLock_);
    saId_ = 0;
    dpInitedCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReSubscribePinCodeInvalid()
{
    std::lock_guard<std::mutex> lock(pinCodeLock_);
    bundleName_.clear();
    pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE;
    pinCodeCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::StartThreadReSubscribePinCodeInvalid()
{
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseSubscribeDeviceProfileSA()
{
    std::lock_guard<std::mutex> lock(saListenerLock_);
    saListenerCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseSubscribeDeviceProfileInited()
{
    std::lock_guard<std::mutex> lock(dpInitedLock_);
    saId_ = 0;
    dpInitedCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseSubscribePinCodeInvalid()
{
    std::lock_guard<std::mutex> lock(pinCodeLock_);
    bundleName_.clear();
    pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE;
    pinCodeCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseDeathRecipient()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    dpDeathRecipient_ = nullptr;
    dpProxy_ = nullptr;
    loadSystemAbilityFinish_ = false;
    proxyConVar_.notify_all();
    HILOGI("%{public}s no-build", __func__);
}

template <typename Method, typename... Args>
int32_t DistributedDeviceProfileClient::RetryClientRequest(
    int32_t firesRet, Method method, Args&& ... args)
{
    (void)firesRet;
    (void)method;
    (void)sizeof...(Args);
    (void)retryErrCodes_.size();
    HILOGI("%{public}s no-build, ret=%{public}d", __func__, DP_NOT_SUPPORT);
    return DP_NOT_SUPPORT;
}

void DistributedDeviceProfileClient::ReRegisterBusinessCallback()
{
    std::lock_guard<std::mutex> lock(businessLock_);
    strSaId_.clear();
    businessKey_.clear();
    businessCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::ReleaseRegisterBusinessCallback()
{
    std::lock_guard<std::mutex> lock(businessLock_);
    strSaId_.clear();
    businessKey_.clear();
    businessCallback_ = nullptr;
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::StartThreadReRegisterBusinessCallback()
{
    HILOGI("%{public}s no-build", __func__);
}

void DistributedDeviceProfileClient::DeviceProfileDeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject>& remote)
{
    HILOGI("%{public}s no-build", __func__);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
