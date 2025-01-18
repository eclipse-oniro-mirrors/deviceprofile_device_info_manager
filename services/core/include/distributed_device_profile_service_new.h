/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "device_icon_info.h"
#include "device_icon_info_filter_options.h"
#include "device_profile_filter_options.h"
#include "distributed_device_profile_stub_new.h"
#include "dp_account_common_event.h"
#include "i_dp_inited_callback.h"
#include "event_handler.h"
#include "event_runner.h"
#include "product_info.h"
#include "single_instance.h"
#include "system_ability.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DistributedDeviceProfileServiceNew : public SystemAbility, public DistributedDeviceProfileStubNew {
    DECLARE_SYSTEM_ABILITY(DistributedDeviceProfileServiceNew);
    DECLARE_SINGLE_INSTANCE_BASE(DistributedDeviceProfileServiceNew);

public:
    DistributedDeviceProfileServiceNew();
    ~DistributedDeviceProfileServiceNew() = default;

    int32_t Init();
    int32_t PostInit();
    int32_t UnInit();
    int32_t PutAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t UpdateAccessControlProfile(const AccessControlProfile& aclProfile) override;
    int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile) override;
    int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles) override;
    int32_t GetAccessControlProfile(std::map<std::string, std::string> queryParams,
        std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles) override;
    int32_t DeleteAccessControlProfile(int32_t accessControlId) override;
    int32_t PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles) override;
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile) override;
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles) override;
    int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile) override;
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles) override;
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile) override;
    int32_t GetDeviceProfiles(DeviceProfileFilterOptions& options, std::vector<DeviceProfile>& deviceProfiles) override;
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
    int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IRemoteObject> dpInitedCallback) override;
    int32_t UnSubscribeDeviceProfileInited(int32_t saId) override;
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo> deviceInfos) override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    void DelayUnloadTask() override;
    bool IsInited() override;
    void SubscribeAccountCommonEvent();

protected:
    void OnStart(const SystemAbilityOnDemandReason& startReason) override;
    void OnStop() override;
    int32_t OnIdle(const SystemAbilityOnDemandReason& idleReason) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    void AccountCommonEventCallback(int32_t userId, const std::string commonEventType);
    int32_t CreateUnloadHandler();
    int32_t DestroyUnloadHandler();
    int32_t AddSvrProfilesToCache(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t AddCharProfilesToCache(const std::vector<CharacteristicProfile>& charProfiles);
    int32_t SaveSwitchProfilesFromTempCache();
    int32_t SaveDynamicProfilesFromTempCache();
    int32_t NotifyDeviceProfileInited();
    void GetDynamicProfilesFromTempCache(std::map<std::string, std::string>& entries);
    void ClearProfileCache();
    int32_t UnInitNext();

private:
    std::mutex accountCommonEventManagerMtx_;
    std::shared_ptr<DpAccountCommonEventManager> accountCommonEventManager_;
    std::shared_ptr<AppExecFwk::EventHandler> unloadHandler_;
    std::mutex unloadMutex_;
    std::atomic<bool> isInited_{false};
    std::mutex dynamicProfileMapMtx_;
    std::map<std::string, std::string> dynamicProfileMap_;
    std::mutex dpInitedCallbackMapMtx_;
    std::map<int32_t, sptr<IRemoteObject>> dpInitedCallbackMap_;
    std::mutex switchProfileMapMtx_;
    std::map<std::string, CharacteristicProfile> switchProfileMap_;
    std::mutex depSaIdsMtx_;
    std::unordered_set<int32_t> depSaIds_ {
        SOFTBUS_SERVER_SA_ID,
        DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID,
        DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN
    };
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H
