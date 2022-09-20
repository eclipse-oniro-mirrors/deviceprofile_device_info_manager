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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H

#include <functional>
#include <iosfwd>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <stdint.h>

#include "event_handler.h"
#include "idistributed_device_profile.h"
#include "iprofile_event_callback.h"
#include "iremote_object.h"
#include "profile_event.h"
#include "profile_event_notifier_stub.h"
#include "refbase.h"
#include "single_instance.h"
#include "subscribe_info.h"

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileClient {
    DECLARE_SINGLE_INSTANCE(DistributedDeviceProfileClient);

public:
    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile);
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile);
    int32_t DeleteDeviceProfile(const std::string& serviceId);
    int32_t SubscribeProfileEvent(const SubscribeInfo& subscribeInfo,
        const std::shared_ptr<IProfileEventCallback>& eventCb);
    int32_t UnsubscribeProfileEvent(ProfileEvent profileEvent,
        const std::shared_ptr<IProfileEventCallback>& eventCb);
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const std::shared_ptr<IProfileEventCallback>& eventCb,
        std::list<ProfileEvent>& failedEvents);
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const std::shared_ptr<IProfileEventCallback>& eventCb,
        std::list<ProfileEvent>& failedEvents);
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions,
        const std::shared_ptr<IProfileEventCallback>& syncCb);

private:
    class DeviceProfileDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    };

    struct SubscribeRecord {
        std::list<SubscribeInfo> subscribeInfos;
        sptr<IRemoteObject> notifier;
        ProfileEvents profileEvents;
    };

    sptr<IDistributedDeviceProfile> GetDeviceProfileService();
    bool CheckProfileInvalidity(const ServiceCharacteristicProfile& profile);
    void OnServiceDied(const sptr<IRemoteObject>& remote);
    void MergeSubscribeInfoLocked(std::list<SubscribeInfo>& subscribeInfos,
        const std::list<SubscribeInfo>& newSubscribeInfos);

    std::mutex serviceLock_;
    std::mutex subscribeLock_;
    sptr<IDistributedDeviceProfile> dpProxy_;
    sptr<IRemoteObject::DeathRecipient> dpDeathRecipient_;
    std::shared_ptr<AppExecFwk::EventHandler> dpClientHandler_;
    std::map<std::shared_ptr<IProfileEventCallback>, SubscribeRecord> subscribeRecords_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_CLIENT_H