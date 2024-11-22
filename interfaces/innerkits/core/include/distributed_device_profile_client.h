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
#include "i_profile_change_listener.h"
#include "i_distributed_device_profile.h"
#include "i_dp_inited_callback.h"
#include "iremote_object.h"
#include "refbase.h"
#include "single_instance.h"
#include "dp_subscribe_info.h"
#include "distributed_device_profile_constants.h"
#include "sync_completed_callback_stub.h"
#include "system_ability_status_change_stub.h"
#include "profile_change_listener_stub.h"
#include "trusted_device_info.h"

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
    int32_t DeleteAccessControlProfile(int32_t accessControlId);
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile);
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t PutCharacteristicProfile(const CharacteristicProfile& characteristicProfile);
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& characteristicProfiles);
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile);
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& characteristicProfile);
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName,
        bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID);
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, bool isMultiUser = false, int32_t userId = DEFAULT_USER_ID);
    int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo);
    int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo);
    int32_t SyncDeviceProfile(const DpSyncOptions& syncOptions, sptr<ISyncCompletedCallback> syncCb);
    int32_t SubscribeDeviceProfileInited(int32_t saId, sptr<IDpInitedCallback> initedCb);
    int32_t UnSubscribeDeviceProfileInited(int32_t saId);
    int32_t PutAllTrustedDevices(const std::vector<TrustedDeviceInfo>& deviceInfos);

    void LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject);
    void LoadSystemAbilityFail();

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

    class DeviceProfileDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject>& remote);
    };
    int32_t saId_ = 0;
    sptr<IDpInitedCallback> dpInitedCallback_ = nullptr;
    std::condition_variable proxyConVar_;
    std::mutex serviceLock_;
    sptr<IDistributedDeviceProfile> dpProxy_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> dpDeathRecipient_ = nullptr;
    std::map<std::string, SubscribeInfo> subscribeInfos_;
    sptr<SystemAbilityListener> saListenerCallback_ = nullptr;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H
