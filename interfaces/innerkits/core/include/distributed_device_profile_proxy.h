/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_PROXY_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_PROXY_H

#include <functional>
#include <iosfwd>
#include <list>
#include <stdint.h>

#include "idistributed_device_profile.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "profile_event.h"
#include "refbase.h"

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileProxy : public IRemoteProxy<IDistributedDeviceProfile> {
public:
    explicit DistributedDeviceProfileProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IDistributedDeviceProfile>(impl) {}
    ~DistributedDeviceProfileProxy() = default;

    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile) override;
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile) override;
    int32_t DeleteDeviceProfile(const std::string& serviceId) override;
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) override;
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) override;
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions,
        const sptr<IRemoteObject>& profileEventNotifier) override;

private:
    static inline BrokerDelegator<DistributedDeviceProfileProxy> delegator_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_PROXY_H