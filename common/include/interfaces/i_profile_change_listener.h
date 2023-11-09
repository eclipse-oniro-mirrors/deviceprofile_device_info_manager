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

#ifndef OHOS_DP_ISUBSCRIBE_PROFILE_LISTENER_H
#define OHOS_DP_ISUBSCRIBE_PROFILE_LISTENER_H

#include "trust_device_profile.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class IProfileChangeListener : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DeviceProfile.IProfileListener");
    IProfileChangeListener() = default;
    virtual ~IProfileChangeListener() = default;
    virtual int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile) = 0;
    virtual int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile) = 0;
    virtual int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile,
        const TrustDeviceProfile& newProfile) = 0;
    virtual int32_t OnDeviceProfileAdd(const DeviceProfile& profile) = 0;
    virtual int32_t OnDeviceProfileDelete(const DeviceProfile& profile) = 0;
    virtual int32_t OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile) = 0;
    virtual int32_t OnServiceProfileAdd(const ServiceProfile& profile) = 0;
    virtual int32_t OnServiceProfileDelete(const ServiceProfile& profile) = 0;
    virtual int32_t OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile) = 0;
    virtual int32_t OnCharacteristicProfileAdd(const CharacteristicProfile& profile) = 0;
    virtual int32_t OnCharacteristicProfileDelete(const CharacteristicProfile& profile) = 0;
    virtual int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
        const CharacteristicProfile& newProfile) = 0;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ISUBSCRIBE_PROFILE_LISTENER_H
