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

#ifndef OHOS_DP_I_DISTRIBUTED_DEVICE_PROFILE_H
#define OHOS_DP_I_DISTRIBUTED_DEVICE_PROFILE_H

#include <list>

#include "iremote_broker.h"
#include "trust_device_profile.h"
#include "access_control_profile.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "dp_subscribe_info.h"
#include "dp_sync_options.h"
#include "i_sync_completed_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class IDistributedDeviceProfile : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DeviceProfile.IDistributedDeviceProfile");
    IDistributedDeviceProfile() = default;
    virtual ~IDistributedDeviceProfile() = default;
    virtual int32_t PutAccessControlProfile(const AccessControlProfile& aclProfile) = 0;
    virtual int32_t UpdateAccessControlProfile(const AccessControlProfile& aclProfile) = 0;
    virtual int32_t GetTrustDeviceProfile(const std::string& deviceId, TrustDeviceProfile& trustDeviceProfile) = 0;
    virtual int32_t GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles) = 0;
    virtual int32_t GetAccessControlProfile(std::map<std::string, std::string> queryParams,
         std::vector<AccessControlProfile>& accessControlProfiles) = 0;
    virtual int32_t GetAllAccessControlProfile(std::vector<AccessControlProfile>& accessControlProfiles) = 0;
    virtual int32_t DeleteAccessControlProfile(int32_t accessControlId) = 0;
    virtual int32_t PutServiceProfile(const ServiceProfile& serviceProfile) = 0;
    virtual int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles) = 0;
    virtual int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile) = 0;
    virtual int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles) = 0;
    virtual int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile) = 0;
    virtual int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile) = 0;
    virtual int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& charProfile) = 0;
    virtual int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName) = 0;
    virtual int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId) = 0;
    virtual int32_t SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) = 0;
    virtual int32_t UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo) = 0;
    virtual int32_t SyncDeviceProfile(const DistributedDeviceProfile::DpSyncOptions& syncOptions,
        sptr<IRemoteObject> syncCompletedCallback) = 0;
    virtual int32_t SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap) = 0;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_I_DISTRIBUTED_DEVICE_PROFILE_H