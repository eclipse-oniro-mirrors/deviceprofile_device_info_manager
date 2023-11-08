/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_SUBSCRIBE_PROFILE_LISTENER_H
#define OHOS_DP_SUBSCRIBE_PROFILE_LISTENER_H

#include "i_profile_change_listener.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "refbase.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileListenerProxy : public IRemoteProxy<IProfileChangeListener> {
public:
    explicit ProfileListenerProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IProfileChangeListener>(impl) {}
    ~ProfileListenerProxy() = default;
    int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile) override;
    int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile) override;
    int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile, const TrustDeviceProfile& newProfile) override;
    int32_t OnDeviceProfileAdd(const DeviceProfile& profile) override;
    int32_t OnDeviceProfileDelete(const DeviceProfile& profile) override;
    int32_t OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile) override;
    int32_t OnServiceProfileAdd(const ServiceProfile& profile) override;
    int32_t OnServiceProfileDelete(const ServiceProfile& profile) override;
    int32_t OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile) override;
    int32_t OnCharacteristicProfileAdd(const CharacteristicProfile& profile) override;
    int32_t OnCharacteristicProfileDelete(const CharacteristicProfile& profile) override;
    int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
        const CharacteristicProfile& newProfile) override;

private:
    static inline BrokerDelegator<ProfileListenerProxy> delegator_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SUBSCRIBE_PROFILE_LISTENER_H
