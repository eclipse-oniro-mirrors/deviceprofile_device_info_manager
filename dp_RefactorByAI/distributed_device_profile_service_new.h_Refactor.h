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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H

#include <atomic>
#include <map>
#include <mutex>
#include <unordered_set>
#include <chrono>
#include <queue>
#include "device_icon_info.h"
#include "device_icon_info_filter_options.h"
#include "device_profile_filter_options.h"
#include "distributed_device_profile_stub_new.h"
#include "dp_account_common_event.h"
#include "event_handler.h"
#include "event_runner.h"
#include "i_dp_inited_callback.h"
#include "local_service_info.h"
#include "product_info.h"
#include "service_info_unique_key.h"
#include "single_instance.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "service_info.h"
#include "user_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {

// 安全增强：操作状态机上下文（原则5：状态机上下文校验）
struct OperationContext {
    int32_t currentState;
    int32_t previousState;
    uint32_t userId;
    std::string deviceId;
    int64_t timestamp;
    bool IsValid() const;
};

// 安全增强：认证限流记录（原则7：防暴力破解）
struct AuthRateLimitRecord {
    int64_t lastAttemptTime;
    int32_t failCount;
    bool IsBlocked() const;
};

// 安全增强：ACL生命周期管理（原则17：ACL三阶段老化）
struct AclLifecycleInfo {
    int64_t createTime;
    int64_t lastAccessTime;
    int32_t accessCount;
    bool IsExpired() const;
};

class DistributedDeviceProfileServiceNew : public SystemAbility, public DistributedDeviceProfileStubNew {
    DECLARE_SYSTEM_ABILITY(DistributedDeviceProfileServiceNew);
    DECLARE_SINGLE_INSTANCE_BASE(DistributedDeviceProfileServiceNew);

public:
    DistributedDeviceProfileServiceNew();
    ~DistributedDeviceProfileServiceNew();

    int32_t Init();
    int32_t PostInit();
    int32_t PostInitNext();
    int32_t UnInit();
    bool ExitIdleState();
    bool IsStopped();
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
    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile) override;
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles) override;
    int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile) override;
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles) override;
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile) override;
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options, std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile) override;
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, CharacteristicProfile& charProfile) override;
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName, bool isMultiUser = false,
        int32_t userId = DEFAULT_USER_ID) override;
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID) override;
    int32_t PutProductInfoBatch(const std::vector<ProductInfo>& productInfos) override;
    int32_t PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
        std::vector<DeviceIconInfo>& deviceIconInfos) override;
    int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) override;
    int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SyncStaticProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IRemoteObject> dpInitedCallback) override;
    int32_t UnSubscribeDeviceProfileInited(int32_t saId) override;
    int32_t SubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType,
        sptr<IRemoteObject> pinCodeCallback) override;
    int32_t UnSubscribePinCodeInvalid(const std::string& bundleName, int32_t pinExchangeType) override;
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos) override;
    int32_t PutLocalServiceInfo(const LocalServiceInfo& localServiceInfo)override;
    int32_t UpdateLocalServiceInfo(const LocalServiceInfo& localServiceInfo)override;
    int32_t GetLocalServiceInfoByBundleAndPinType(const std::string& bundleName,
        int32_t pinExchangeType, LocalServiceInfo& localServiceInfo)override;
    int32_t DeleteLocalServiceInfo(const std::string& bundleName, int32_t pinExchangeType)override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    void DelayUnloadTask() override;
    bool IsInited() override;
    bool IsReadyIntoIdle();
    void AddRunningIpcCount();
    void SubtractRunningIpcCount();
    void SubscribeAccountCommonEvent();
    int32_t RegisterBusinessCallback(const std::string& saId, const std::string& businessKey,
        sptr<IRemoteObject> businessCallback) override;
    int32_t UnRegisterBusinessCallback(const std::string& saId, const std::string& businessKey) override;
    int32_t PutBusinessEvent(const BusinessEvent& event) override;
    int32_t GetBusinessEvent(BusinessEvent& event) override;
    int32_t PutServiceInfo(const ServiceInfo& serviceInfo) override;
    int32_t DeleteServiceInfo(const UserInfo& userInfo) override;
    int32_t GetAllServiceInfoList(std::vector<ServiceInfo>& serviceInfos) override;
    int32_t GetServiceInfosByUserInfo(const UserInfo& userInfo,
        std::vector<ServiceInfo>& serviceInfos) override;
    int32_t SubscribeAllServiceInfo(int32_t saId, sptr<IRemoteObject> listener) override;

protected:
    void OnStart(const SystemAbilityOnDemandReason& startReason) override;
    void OnStop() override;
    void OnActive(const SystemAbilityOnDemandReason& activeReason) override;
    int32_t OnIdle(const SystemAbilityOnDemandReason& idleReason) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    // 安全增强函数（原则4、12、14等）
    bool ValidateOperationContext(const std::string& deviceId, uint32_t userId);
    bool CheckAuthRateLimit(const std::string& identifier);
    void SecureClearVector(std::vector<uint8_t>& data);
    void SecureClearString(std::string& data);
    std::vector<uint8_t> EncryptSensitiveData(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> DecryptSensitiveData(const std::vector<uint8_t>& ciphertext);
    bool ValidateDeviceIntegrity(const std::string& deviceId);
    void UpdateAclLifecycleInfo(const std::string& aclKey);
    bool CheckAclLifecycle(const std::string& aclKey);
    void CleanupExpiredAcls();
    int32_t PerformDualEndAclCheck(const AccessControlProfile& aclProfile);
    bool ValidateUserIsolation(uint32_t userId, const std::string& deviceId);
    void EnforceMinLifecycle(const std::string& resourceKey);
    bool IsSwitchStatusValid();
    int32_t ValidatePinCodeSecurity(const std::string& pinCode);
    void RecordAuthAttempt(const std::string& identifier, bool success);

    void AccountCommonEventCallback(int32_t userId, const std::string commonEventType);
    int32_t CreateUnloadHandler();
    int32_t DestroyUnloadHandler();
    int32_t AddSvrProfilesToCache(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t AddCharProfilesToCache(const std::vector<CharacteristicProfile>& charProfiles);
    int32_t SaveSwitchProfilesFromTempCache();
    int32_t SaveDynamicProfilesFromTempCache();
    int32_t NotifyDeviceProfileInited();
    int32_t NotifyPinCodeInvalid(const LocalServiceInfo& localServiceInfo);
    int32_t NotifyBusinessEvent(const BusinessEvent& event);
    void GetDynamicProfilesFromTempCache(std::map<std::string, std::string>& entries);
    void ClearProfileCache();
    int32_t UnInitNext();
    int32_t PutCharacteristicProfileBatchPreprocess(const std::vector<CharacteristicProfile>& charProfiles);

private:
    std::mutex accountCommonEventManagerMtx_;
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager_;
    std::shared_ptr<AppExecFwk::EventHandler> unloadHandler_;
    std::mutex unloadMutex_;
    std::atomic<bool> isInited_{false};
    std::atomic<bool> isStopped_{false};
    std::atomic<int32_t> runningIpcCount_{0};
    std::mutex dynamicProfileMapMtx_;
    std::map<std::string, std::string> dynamicProfileMap_;
    std::mutex dpInitedCallbackMapMtx_;
    std::map<int32_t, sptr<IRemoteObject>> dpInitedCallbackMap_;
    std::mutex pinCodeCallbackMapMtx_;
    std::map<std::pair<std::string, int32_t>, sptr<IRemoteObject>> pinCodeCallbackMap_;
    std::mutex switchProfileMapMtx_;
    std::map<std::string, CharacteristicProfile> switchProfileMap_;
    std::mutex depSaIdsMtx_;
    std::unordered_set<int32_t> depSaIds_ {
        SOFTBUS_SERVER_SA_ID,
        DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID,
        DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
        MEMORY_MANAGER_SA_ID
    };
    std::mutex businessEventCallbackMapMtx_;
    std::mutex cacheMtx_;
    std::map<std::pair<std::string, std::string>, sptr<IRemoteObject>> businessCallbackMap_;

    // 安全增强成员变量（原则5、7、12、17等）
    std::mutex operationContextMtx_;
    std::map<std::string, OperationContext> operationContextMap_;

    std::mutex authRateLimitMtx_;
    std::map<std::string, AuthRateLimitRecord> authRateLimitMap_;

    std::mutex aclLifecycleMtx_;
    std::map<std::string, AclLifecycleInfo> aclLifecycleMap_;

    std::mutex userIsolationMtx_;
    std::map<uint32_t, std::set<std::string>> userDeviceMap_;

    std::atomic<bool> securityInitialized_{false};
    int32_t securitySwitchStatus_ = -1; // 原则13：开关默认值为非法值
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H
