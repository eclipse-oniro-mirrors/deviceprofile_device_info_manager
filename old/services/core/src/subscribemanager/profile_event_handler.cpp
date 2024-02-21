/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "profile_event_handler.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_utils.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ProfileEventHandler";
}

bool ProfileEventHandler::Init()
{
    auto runner = AppExecFwk::EventRunner::Create(handlerName_);
    eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    if (eventHandler_ == nullptr) {
        return false;
    }
    return true;
}

int32_t ProfileEventHandler::Subscribe(const SubscribeInfo& subscribeInfo,
    const sptr<IRemoteObject>& profileEventNotifier)
{
    std::lock_guard<std::mutex> autoLock(notifierLock_);
    auto iter = profileEventSubscribeInfos_.find(profileEventNotifier);
    if (iter == profileEventSubscribeInfos_.end()) {
        if (subscribeInfo.extraInfo.contains("deviceId") && subscribeInfo.extraInfo.contains("serviceIds")) {
            HILOGI("add subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(subscribeInfo.extraInfo["deviceId"].get<std::string>()).c_str(),
                subscribeInfo.extraInfo["serviceIds"].dump().c_str());
        } else {
            HILOGI("add subscribeInfo without deviceId and serviceIds");
        }
        profileEventSubscribeInfos_.emplace(profileEventNotifier, std::move(subscribeInfo));
        HILOGI("profileEventSubscribeInfos_ size = %{public}zu", profileEventSubscribeInfos_.size());
        for (const auto& entry : profileEventSubscribeInfos_) {
            const SubscribeInfo& subscribeInfo = entry.second;
            if (subscribeInfo.extraInfo.contains("deviceId") && subscribeInfo.extraInfo.contains("serviceIds")) {
                HILOGI("subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
                    DeviceProfileUtils::AnonymizeDeviceId(
                        subscribeInfo.extraInfo["deviceId"].get<std::string>()).c_str(),
                    subscribeInfo.extraInfo["serviceIds"].dump().c_str());
            } else {
                HILOGI("subscribeInfo without deviceId and serviceIds");
            }
        }
    } else {
        // just overwrite when the follow-ups subscribe with the same notifier
        HILOGW("overwrite last subscribed info");
        if (subscribeInfo.extraInfo.contains("deviceId") && subscribeInfo.extraInfo.contains("serviceIds")) {
            HILOGI("update subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(subscribeInfo.extraInfo["deviceId"].get<std::string>()).c_str(),
                subscribeInfo.extraInfo["serviceIds"].dump().c_str());
        } else {
            HILOGI("update subscribeInfo without deviceId and serviceIds");
        }
        iter->second = std::move(subscribeInfo);
        HILOGI("profileEventSubscribeInfos_ size = %{public}zu", profileEventSubscribeInfos_.size());
        for (const auto& entry : profileEventSubscribeInfos_) {
            const SubscribeInfo& subscribeInfo = entry.second;
            if (subscribeInfo.extraInfo.contains("deviceId") && subscribeInfo.extraInfo.contains("serviceIds")) {
                HILOGI("subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
                    DeviceProfileUtils::AnonymizeDeviceId(
                        subscribeInfo.extraInfo["deviceId"].get<std::string>()).c_str(),
                    subscribeInfo.extraInfo["serviceIds"].dump().c_str());
            } else {
                HILOGI("subscribeInfo without deviceId and serviceIds");
            }
        }
    }

    if (!isRegistered_) {
        int32_t errCode = Register();
        if (errCode != ERR_OK) {
            HILOGE("errCode = %{public}d", errCode);
            return ERR_DP_SUBSCRIBE_FAILED;
        }
        isRegistered_ = true;
    }
    return ERR_OK;
}

int32_t ProfileEventHandler::Unsubscribe(const sptr<IRemoteObject>& profileEventNotifier)
{
    std::lock_guard<std::mutex> autoLock(notifierLock_);
    auto iter = profileEventSubscribeInfos_.find(profileEventNotifier);
    if (iter == profileEventSubscribeInfos_.end()) {
        HILOGW("not subscribe yet");
        return ERR_DP_NOT_SUBSCRIBED;
    }
    if (iter->second.extraInfo.contains("deviceId") && iter->second.extraInfo.contains("serviceIds")) {
        HILOGI("remove subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(iter->second.extraInfo["deviceId"].get<std::string>()).c_str(),
                iter->second.extraInfo["serviceIds"].dump().c_str());
    } else {
        HILOGI("remove subscribeInfo without deviceId and serviceIds");
    }
    profileEventSubscribeInfos_.erase(iter);
    HILOGI("profileEventSubscribeInfos_ size = %{public}zu", profileEventSubscribeInfos_.size());
    for (const auto& entry : profileEventSubscribeInfos_) {
        const SubscribeInfo& subscribeInfo = entry.second;
        if (subscribeInfo.extraInfo.contains("deviceId") && subscribeInfo.extraInfo.contains("serviceIds")) {
            HILOGI("subscribeInfo: deviceId = %{public}s, serviceIds = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(subscribeInfo.extraInfo["deviceId"].get<std::string>()).c_str(),
                subscribeInfo.extraInfo["serviceIds"].dump().c_str());
        } else {
            HILOGI("subscribeInfo without deviceId and serviceIds");
        }
    }
    if (profileEventSubscribeInfos_.empty()) {
        int32_t errCode = Unregister();
        if (errCode != ERR_OK) {
            HILOGE("errCode = %{public}d", errCode);
            return ERR_DP_UNSUBSCRIBE_FAILED;
        }
        isRegistered_ = false;
    }
    return ERR_OK;
}

void ProfileEventHandler::OnSubscriberDied(const sptr<IRemoteObject>& profileEventNotifier)
{
    HILOGD("called");
    Unsubscribe(profileEventNotifier);
}

bool ProfileEventHandler::IsRegistered() const
{
    return isRegistered_;
}
} // namespace DeviceProfile
} // namespace OHOS
