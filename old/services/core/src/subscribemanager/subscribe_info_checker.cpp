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

#include "subscribe_info_checker.h"

#include "device_profile_log.h"
#include "profile_event.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SubscribeInfoChecker";
}

IMPLEMENT_SINGLE_INSTANCE(SubscribeInfoChecker);

SubscribeInfoChecker::SubscribeInfoChecker()
{
    checkersMap_[EVENT_SYNC_COMPLETED] = &SubscribeInfoChecker::CheckSyncEventInner;
    checkersMap_[EVENT_PROFILE_CHANGED] = &SubscribeInfoChecker::CheckProfileChangeInner;
}

bool SubscribeInfoChecker::Check(const std::list<SubscribeInfo>& subscribeInfos)
{
    auto checker = [this](const auto& subscribeInfo) {
        auto profileEvent = subscribeInfo.profileEvent;
        auto iter = checkersMap_.find(profileEvent);
        if (iter != checkersMap_.end()) {
            auto func = iter->second;
            if (func != nullptr) {
                return (this->*func)(subscribeInfo);
            }
        }
        HILOGE("unknown profile event = %{public}u", static_cast<uint32_t>(profileEvent));
        return false;
    };
    return std::all_of(subscribeInfos.begin(), subscribeInfos.end(), checker);
}

bool SubscribeInfoChecker::CheckSyncEventInner([[maybe_unused]] const SubscribeInfo& subscribeInfo)
{
    // currently no need to check for sync event
    return true;
}

bool SubscribeInfoChecker::CheckProfileChangeInner(const SubscribeInfo& subscribeInfo)
{
    const ExtraInfo& extraInfo = subscribeInfo.extraInfo;
    const auto& deviceIdJson = extraInfo["deviceId"];
    if (deviceIdJson == nullptr) {
        return false;
    }
    HILOGD("check deviceId");
    if (deviceIdJson.type() != ExtraInfo::value_t::string) {
        return false;
    }

    const auto& serviceIdsJson = extraInfo["serviceIds"];
    if (serviceIdsJson == nullptr) {
        return false;
    }
    HILOGD("check serviceIds");
    auto type = serviceIdsJson.type();
    if (type != ExtraInfo::value_t::array) {
        return false;
    } else {
        return std::all_of(serviceIdsJson.begin(), serviceIdsJson.end(),
            [](const auto& serviceIdJson) { return serviceIdJson.type() == ExtraInfo::value_t::string; });
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS