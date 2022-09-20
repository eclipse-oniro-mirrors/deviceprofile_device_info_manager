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

#ifndef OHOS_DEVICE_PROFILE_SUBSCRIBE_MANAGER_H
#define OHOS_DEVICE_PROFILE_SUBSCRIBE_MANAGER_H

#include <map>
#include <unordered_set>
#include <bitset>
#include <list>

#include "iremote_object.h"
#include "single_instance.h"
#include "iprofile_event_notifier.h"
#include "profile_event.h"
#include "profile_change_notification.h"

#include "profile_event_handler.h"
#include "subscribe_info.h"

namespace OHOS {
namespace DeviceProfile {
class SubscribeManager {
    DECLARE_SINGLE_INSTANCE(SubscribeManager);

public:
    bool Init();

    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents);
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents);

    void OnSubscriberDied(const sptr<IRemoteObject>& profileEventNotifier);

private:
    struct NotifierInfo {
        int32_t callingUid;
        ProfileEvents profileEvents;
    };

    void TryAddNotifierLocked(const sptr<IRemoteObject>& profileEventNotifier,
        const ProfileEvents& profileEvents);
    void TryRemoveNotiferLocked(const sptr<IRemoteObject>& profileEventNotifier,
        const ProfileEvents& profileEvents);
    void IncSubsOfUidLocked(int32_t uid);
    void DecSubsOfUidLocked(int32_t uid);
    bool CheckSubsOfUid(int32_t uid);

private:
    std::mutex handlerLock_;
    std::map<sptr<IRemoteObject>, NotifierInfo> notifiersMap_;
    std::map<ProfileEvent, std::shared_ptr<ProfileEventHandler>> handlersMap_;
    std::unordered_map<int32_t, uint32_t> uidSubsMap_;
    sptr<IRemoteObject::DeathRecipient> subscriberDeathRecipient_;
};
}  // namespace DeviceProfile
}  // namespace OHOS
#endif  // OHOS_DEVICE_PROFILE_SUBSCRIBE_MANAGER_H
