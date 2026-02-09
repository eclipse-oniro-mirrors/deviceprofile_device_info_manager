/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H

#include <functional>
#include <iosfwd>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <set>
#include <condition_variable>
#include "i_pincode_invalid_callback.h"
#include "i_profile_change_listener.h"
#include "i_distributed_device_profile.h"
#include "i_dp_inited_callback.h"
#include "iremote_object.h"
#include "refbase.h"
#include "single_instance.h"
#include "dp_subscribe_info.h"
#include "distributed_device_profile_constants.h"
#include "ibusiness_callback.h"
#include "sync_completed_callback_stub.h"
#include "system_ability_status_change_stub.h"
#include "profile_change_listener_stub.h"
#include "trusted_device_info.h"
#include "local_service_info.h"
#include "iremote_broker.h"
#include "user_info.h"
#include "service_info_profile_new.h"
#include "service_info_profile.h"


namespace OHOS {
namespace DistributedDeviceProfile {
class DistributedDeviceProfileClient {
DECLARE_SINGLE_INSTANCE(DistributedDeviceProfileClient);

public:
    int32_t PutAccessControlProfile(const AccessControlProfile& accessControlProfile);
    int32_t UpdateAccessControlProfile(const AccessControlProfile& accessControlProfile);
    int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile);
    int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles);
    int32_t GetAccessControlProfile(std::map<std::string, std::string> params,
        std::vector<AccessControlProfile>& accessControlProfiles);
    int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles);
    int32_t GetAllAclIncludeLnnAcl(std::vector<AccessControlProfile>& accessControlProfiles);
    int32_t DeleteAccessControlProfile(int32_t accessControlId);
    int32_t PutSessionKey(uint32_t userId, const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId);
    int32_t GetSessionKey(uint32_t userId, int32_t sessionKeyId, std::vector<uint8_t>& sessionKey);
    int32_t UpdateSessionKey(uint32_t userId, int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey);
    int32_t DeleteSessionKey(uint32_t userId, int32_t sessionKeyId);
    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles);
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile);
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t PutCharacteristicProfile(const CharacteristicProfile& characteristicProfile);
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& characteristicProfiles);
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile);
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options, std::vector<DeviceProfile>& deviceProfiles);
    int32_t DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles);
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& characteristicProfile);
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName,
        bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID);
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID);
    int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos);
    int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos);
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos);
    int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo);
    int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo);
    int32_t SyncDeviceProfile(const DpSyncOptions& syncOptions, sptr<ISyncCompletedCallback> syncCb);
    int32_t SyncStaticProfile(const DpSyncOptions& syncOptions, sptr<ISyncCompletedCallback> syncCb);
    int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IDpInitedCallback> initedCb);
    int32_t UnSubscribeDeviceProfileInited(int32_t saId);
    int32_t SubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType,
        sptr<IPincodeInvalidCallback> pinCodeCallback);
    int32_t UnSubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType);
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo>& deviceInfos);
    int32_t PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo);
    int32_t UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo);
    int32_t GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
        int32_t pinExchangeType, LocalServiceInfo& localServiceInfo);
    int32_t DeleteLocalServiceInfo(const std::string& bundleName, int32_t pinExchangeType);
    int32_t RegisterBusinessCallback(const std::string& saId, const std::string& businessKey,
        sptr<IBusinessCallback> businessCallback);
    int32_t UnRegisterBusinessCallback(const std::string& saId, const std::string& businessKey);
    int32_t PutBusinessEvent(const BusinessEvent& event);
    int32_t GetBusinessEvent(BusinessEvent& event);
    int32_t PutServiceInfo(const ServiceInfo& serviceInfo);
    int32_t DeleteServiceInfo(const UserInfo& userInfo);
    int32_t GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos);
    int32_t GetServiceInfosByUserInfo(const UserInfo& userInfo, std::vector<ServiceInfo>& serviceInfos);
    int32_t SubscribeAllServiceInfo(int32_t saId, sptr<IRemoteObject> listener);

    void LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject);
    void LoadSystemAbilityFail();
    void ReleaseResource();
    void ReSubscribeAllServiceInfo();
    //delete start
    int32_t UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile);
    int32_t GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key, ServiceInfoProfile& serviceInfoProfile);
    int32_t GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    int32_t GetAllServiceInfoProfileList(std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    int32_t GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
        std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    int32_t PutServiceInfoProfile(const ServiceInfoProfileNew& serviceInfoProfile);
    int32_t DeleteServiceInfoProfile(int32_t regServiceId, int32_t userId);
    int32_t GetServiceInfoProfileByServiceId(int64_t serviceId, ServiceInfoProfileNew& serviceInfoProfile);
    int32_t GetServiceInfoProfileByTokenId(int64_t tokenId, std::vector<ServiceInfoProfileNew>& serviceInfoProfiles);
    int32_t GetServiceInfoProfileByRegServiceId(int32_t regServiceId, ServiceInfoProfileNew& serviceInfoProfile);
    //delete end

public:
    class SystemAbilityListener : public SystemAbilityStatusChangeStub {
    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    };

private:
    void SendSubscribeInfosToService();
    sptr<IDistributedDeviceProfile> LoadDeviceProfileService();
    sptr<IDistributedDeviceProfile> GetDeviceProfileService();
    void OnServiceDied(const sptr<IRemoteObject>& remote);
    void SubscribeDeviceProfileSA();
    void StartThreadSendSubscribeInfos();
    void ReSubscribeDeviceProfileInited();
    void ReSubscribePinCodeInvalid();
    void StartThreadReSubscribePinCodeInvalid();
    void ReleaseSubscribeDeviceProfileSA();
    void ReleaseSubscribeDeviceProfileInited();
    void ReleaseSubscribePinCodeInvalid();
    void ReleaseDeathRecipient();
    template <typename Method, typename... Args>
    int32_t RetryClientRequest(int32_t firesRet, Method method, Args&& ... args);
    void ReRegisterBusinessCallback();
    void ReleaseRegisterBusinessCallback();
    void StartThreadReRegisterBusinessCallback();

    class DeviceProfileDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject>& remote);
    };
    std::mutex dpInitedLock_;
    int32_t saId_ = 0;
    sptr<IDpInitedCallback> dpInitedCallback_ = nullptr;

    std::mutex pinCodeLock_;
    sptr<IPincodeInvalidCallback> pinCodeCallback_ = nullptr;
    std::string bundleName_ = "";
    int32_t pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE;

    std::mutex serviceLock_;
    std::condition_variable proxyConVar_;
    sptr<IDistributedDeviceProfile> dpProxy_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> dpDeathRecipient_ = nullptr;

    std::mutex subscribeLock_;
    std::map<std::string, SubscribeInfo> subscribeInfos_;

    std::mutex saListenerLock_;
    sptr<SystemAbilityListener> saListenerCallback_ = nullptr;

    const std::set<int32_t> retryErrCodes_ = {DP_SERVICE_STOPPED, DP_LOAD_SERVICE_ERR};
    std::mutex businessLock_;
    sptr<IBusinessCallback> businessCallback_ = nullptr;
    std::string strSaId_ = "";
    std::string businessKey_ = "";

    int32_t serviceInfoSaId_ = 0;
    std::mutex serInfolistenerLock_;
    sptr<IRemoteObject> serviceInfolistener_ = nullptr;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H
