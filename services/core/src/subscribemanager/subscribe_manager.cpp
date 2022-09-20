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

#include "subscribe_manager.h"

#include "ipc_object_proxy.h"
#include "ipc_skeleton.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "profile_change_handler.h"
#include "profile_event_handler_factory.h"
#include "subscribe_info_checker.h"
#include "subscriber_death_recipient.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SubscribeManager";

constexpr int32_t MAX_SUBSCRIBS_PER_UID = 100;
}

IMPLEMENT_SINGLE_INSTANCE(SubscribeManager);

bool SubscribeManager::Init()
{
    subscriberDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) SubscriberDeathRecipient);
    if (subscriberDeathRecipient_ == nullptr) {
        HILOGE("null death recipient");
        return false;
    }
    HILOGI("init succeeded");
    return true;
}

int32_t SubscribeManager::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    HILOGI("called");
    if (!SubscribeInfoChecker::GetInstance().Check(subscribeInfos)) {
        HILOGE("SubscribeInfo check failed");
        return ERR_DP_INVALID_PARAMS;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!CheckSubsOfUid(callingUid)) {
        HILOGE("uid %{public}d subscribed too many times", callingUid);
        return ERR_DP_SUBSCRIBE_LIMIT_EXCEEDED;
    }

    std::lock_guard<std::mutex> autoLock(handlerLock_);
    ProfileEvents subProfileEvents;
    std::shared_ptr<ProfileEventHandler> handler;
    for (const auto& subscribeInfo : subscribeInfos) {
        auto profileEvent = subscribeInfo.profileEvent;
        auto iter = handlersMap_.find(profileEvent);
        if (iter == handlersMap_.end()) {
            handler = ProfileEventHandlerFactory::GetInstance().GetHandler(profileEvent);
            if (handler == nullptr || !handler->Init()) {
                failedEvents.emplace_back(profileEvent);
                HILOGW("get or init handler for event:%{public}d failed", profileEvent);
                continue;
            }
            handlersMap_.emplace(profileEvent, handler);
        } else {
            handler = iter->second;
        }

        if (handler->Subscribe(subscribeInfo, profileEventNotifier) != ERR_OK) {
            HILOGE("subscribe event:%{public}d failed", profileEvent);
            failedEvents.emplace_back(profileEvent);
        } else {
            subProfileEvents.set(static_cast<uint32_t>(profileEvent));
        }
    }
    if (!subProfileEvents.none()) {
        TryAddNotifierLocked(profileEventNotifier, subProfileEvents);
    }
    return failedEvents.empty() ? ERR_OK : ERR_DP_SUBSCRIBE_FAILED;
}

int32_t SubscribeManager::UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(handlerLock_);
    ProfileEvents unsubProfileEvents;
    for (auto profileEvent : profileEvents) {
        auto iter = handlersMap_.find(profileEvent);
        if (iter == handlersMap_.end()) {
            HILOGW("not find event:%{public}d", profileEvent);
            continue;
        }
        auto handler = iter->second;
        if (handler->Unsubscribe(profileEventNotifier) != ERR_OK) {
            HILOGE("unsubscribe event:%{public}d failed", profileEvent);
            failedEvents.emplace_back(profileEvent);
        } else {
            unsubProfileEvents.set(static_cast<uint32_t>(profileEvent));
        }
    }
    if (!unsubProfileEvents.none()) {
        TryRemoveNotiferLocked(profileEventNotifier, unsubProfileEvents);
    }
    return failedEvents.empty() ? ERR_OK : ERR_DP_UNSUBSCRIBE_FAILED;
}

void SubscribeManager::TryAddNotifierLocked(const sptr<IRemoteObject>& profileEventNotifier,
    const ProfileEvents& subProfileEvents)
{
    auto iter = notifiersMap_.find(profileEventNotifier);
    if (iter == notifiersMap_.end()) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        NotifierInfo notifierInfo = { callingUid, subProfileEvents};
        notifiersMap_.emplace(profileEventNotifier, std::move(notifierInfo));
        profileEventNotifier->AddDeathRecipient(subscriberDeathRecipient_);
        HILOGI("notifiers size = %{public}zu", notifiersMap_.size());
        IncSubsOfUidLocked(callingUid);
    } else {
        iter->second.profileEvents |= subProfileEvents;
    }
}

void SubscribeManager::TryRemoveNotiferLocked(const sptr<IRemoteObject>& profileEventNotifier,
    const ProfileEvents& unsubProfileEvents)
{
    auto iter = notifiersMap_.find(profileEventNotifier);
    if (iter == notifiersMap_.end()) {
        return;
    }
    auto& subProfileEvents = iter->second.profileEvents;
    subProfileEvents &= ~unsubProfileEvents;
    if (subProfileEvents.none()) {
        int32_t callingUid = iter->second.callingUid;
        profileEventNotifier->RemoveDeathRecipient(subscriberDeathRecipient_);
        notifiersMap_.erase(iter);
        HILOGI("notifiers size = %{public}zu", notifiersMap_.size());
        DecSubsOfUidLocked(callingUid);
        return;
    }
}

void SubscribeManager::IncSubsOfUidLocked(int32_t uid)
{
    if (uidSubsMap_.find(uid) != uidSubsMap_.end()) {
       ++uidSubsMap_[uid];
    } else {
        uidSubsMap_[uid] = 1;
    }
    HILOGI("uid %{public}d has %{public}u subscription(s)", uid, uidSubsMap_[uid]);
}

void SubscribeManager::DecSubsOfUidLocked(int32_t uid)
{
    auto iter = uidSubsMap_.find(uid);
    if (iter != uidSubsMap_.end()) {
        auto& numSubs = iter->second;
        if (--numSubs == 0) {
            uidSubsMap_.erase(iter);
        }
        HILOGI("uid %{public}d subscription(s) is %{public}u", uid, numSubs);
    }
}

bool SubscribeManager::CheckSubsOfUid(int32_t uid)
{
    std::lock_guard<std::mutex> autoLock(handlerLock_);
    auto iter = uidSubsMap_.find(uid);
    if (iter == uidSubsMap_.end()) {
        return true;
    }
    if (iter->second >= MAX_SUBSCRIBS_PER_UID) {
        return false;
    }
    return true;
}

void SubscribeManager::OnSubscriberDied(const sptr<IRemoteObject>& profileEventNotifier)
{
    HILOGI("called");
    DeviceProfileStorageManager::GetInstance().NotifySubscriberDied(profileEventNotifier);
    std::lock_guard<std::mutex> autoLock(handlerLock_);
    auto iter = notifiersMap_.find(profileEventNotifier);
    if (iter != notifiersMap_.end()) {
        DecSubsOfUidLocked(iter->second.callingUid);
        notifiersMap_.erase(iter);
    }
    for (const auto& [_, handler] : handlersMap_) {
        handler->OnSubscriberDied(profileEventNotifier);
    }
}
} // namespace DeviceProfile
} // namespace OHOS