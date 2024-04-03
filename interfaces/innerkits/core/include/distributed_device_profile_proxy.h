/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_PROXY_H
#define OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_PROXY_H

#include <functional>
#include <iosfwd>
#include <list>
#include <stdint.h>

#include "i_distributed_device_profile.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "refbase.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_errors.h"
#include "ipc_utils.h"
#include "profile_change_listener_stub.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DistributedDeviceProfileProxy : public IRemoteProxy<IDistributedDeviceProfile> {
public:
    explicit DistributedDeviceProfileProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IDistributedDeviceProfile>(impl) {}
    ~DistributedDeviceProfileProxy() {}

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
    int32_t SyncDeviceProfile(const DpSyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback) override;
    int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) override;

private:
    static inline BrokerDelegator<DistributedDeviceProfileProxy> delegator_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DISTRIBUTED_DEVICE_PROFILE_PROXY_H