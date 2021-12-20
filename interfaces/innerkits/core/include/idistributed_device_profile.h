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

#ifndef OHOS_I_DISTRIBUTED_DEVICE_PROFILE_H
#define OHOS_I_DISTRIBUTED_DEVICE_PROFILE_H

#include <list>

#include "iremote_broker.h"
#include "service_characteristic_profile.h"
#include "iprofile_event_notifier.h"
#include "profile_event.h"
#include "subscribe_info.h"
#include "sync_options.h"

namespace OHOS {
namespace DeviceProfile {
class IDistributedDeviceProfile : public IRemoteBroker {
public:
    enum {
        PUT_DEVICE_PROFILE = 1,
        GET_DEVICE_PROFILE = 2,
        DELETE_DEVICE_PROFILE = 3,
        SUBSCRIBE_PROFILE_EVENT = 4,
        UNSUBSCRIBE_PROFILE_EVENT = 5,
        SYNC_DEVICE_PROFILE = 6
    };

    virtual int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile) = 0;
    virtual int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile) = 0;
    virtual int32_t DeleteDeviceProfile(const std::string& serviceId) = 0;
    virtual int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) = 0;
    virtual int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) = 0;
    virtual int32_t SyncDeviceProfile(const SyncOptions& syncOptions,
        const sptr<IRemoteObject>& profileEventNotifier) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DeviceProfile.IDistributedDeviceProfile");
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_I_DISTRIBUTED_DEVICE_PROFILE_H