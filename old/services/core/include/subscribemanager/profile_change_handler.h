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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_PROFILE_CHANGE_HANDLER_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_PROFILE_CHANGE_HANDLER_H

#include <vector>

#include "profile_change_notification.h"
#include "profile_event_handler.h"

#include "kvstore_observer.h"

namespace OHOS {
namespace DeviceProfile {
class ProfileChangeHandler : public std::enable_shared_from_this<ProfileChangeHandler>,
                             public ProfileEventHandler,
                             public DistributedKv::KvStoreObserver {
public:
    explicit ProfileChangeHandler(const std::string& handlerName)
        : ProfileEventHandler(handlerName) {}
    ~ProfileChangeHandler() = default;

    void OnChange(const DistributedKv::ChangeNotification& changeNotification) override;

private:
    int32_t Register() override;
    int32_t Unregister() override;
    int32_t Subscribe(const SubscribeInfo& subscribeInfo,
        const sptr<IRemoteObject>& profileEventNotifier) override;

    void ConvertEntry(const std::vector<DistributedKv::Entry>& entries, ProfileChangeType changeType,
        std::vector<ProfileEntry>& profileEntries, Service2Index& service2Index);

    void NotifyProfileChanged(const ProfileChangeNotification& changeNotification,
        const Service2Index& service2Index);
    void FilterChangedProfileLocked(const SubscribeInfo& subscribeInfo,
        const ProfileChangeNotification& changeNotification,
        const Service2Index& service2Index, FilterInfo& filterInfo);
    void NotifyProfileChangedLocked(const ProfileChangeNotification& changeNotification,
        const FilterInfo& filterInfo,
        const sptr<IProfileEventNotifier>& profileEventNotifier);
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_PROFILE_CHANGE_HANDLER_H
