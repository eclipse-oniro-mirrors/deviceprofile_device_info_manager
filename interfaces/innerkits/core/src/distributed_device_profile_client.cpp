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

#include "distributed_device_profile_client.h"

#include <algorithm>
#include <bitset>
#include <chrono>
#include <functional>
#include <new>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "event_handler.h"
#include "event_runner.h"
#include "idistributed_device_profile.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "profile_event_notifier_stub.h"
#include "service_characteristic_profile.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DeviceProfile {
using namespace std::chrono_literals;

namespace {
const std::string TAG = "DistributedDeviceProfileClient";
const std::string JSON_NULL = "null";
constexpr int32_t RETRY_TIMES_GET_SERVICE = 5;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedDeviceProfileClient);

int32_t DistributedDeviceProfileClient::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    if (CheckProfileInvalidity(profile)) {
        return ERR_DP_INVALID_PARAMS;
    }

    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }
    return dps->PutDeviceProfile(profile);
}

int32_t DistributedDeviceProfileClient::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }
    return dps->GetDeviceProfile(udid, serviceId, profile);
}

int32_t DistributedDeviceProfileClient::DeleteDeviceProfile(const std::string& serviceId)
{
    if (serviceId.empty()) {
        return ERR_DP_INVALID_PARAMS;
    }

    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }
    return dps->DeleteDeviceProfile(serviceId);
}

int32_t DistributedDeviceProfileClient::SubscribeProfileEvent(const SubscribeInfo& subscribeInfo,
    const std::shared_ptr<IProfileEventCallback>& eventCb)
{
    std::list<SubscribeInfo> subscribeInfos;
    subscribeInfos.emplace_back(subscribeInfo);
    std::list<ProfileEvent> failedEvents;
    return SubscribeProfileEvents(subscribeInfos, eventCb, failedEvents);
}

int32_t DistributedDeviceProfileClient::SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
    const std::shared_ptr<IProfileEventCallback>& eventCb,
    std::list<ProfileEvent>& failedEvents)
{
    if (subscribeInfos.empty() || eventCb == nullptr) {
        return ERR_DP_INVALID_PARAMS;
    }

    ProfileEvents subProfileEvents;
    for (auto& subscribeInfo : subscribeInfos) {
        subProfileEvents.set(static_cast<uint32_t>(subscribeInfo.profileEvent));
    }
    // duplicated profile event is disallowed
    if (subProfileEvents.count() != subscribeInfos.size()) {
        return ERR_DP_INVALID_PARAMS;
    }

    std::unique_lock<std::mutex> autoLock(subscribeLock_);
    sptr<IRemoteObject> notifier;
    auto iter = subscribeRecords_.find(eventCb);
    if (iter != subscribeRecords_.end()) {
        notifier = iter->second.notifier;
    } else {
        notifier = sptr<ProfileEventNotifierStub>(
            new ProfileEventNotifierStub(eventCb));
    }
    autoLock.unlock();

    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }

    failedEvents.clear();
    int32_t errCode = dps->SubscribeProfileEvents(subscribeInfos, notifier, failedEvents);
    for (auto failedEvent : failedEvents) {
        subProfileEvents.reset(static_cast<uint32_t>(failedEvent));
    }

    autoLock.lock();
    iter = subscribeRecords_.find(eventCb);
    if (iter != subscribeRecords_.end()) {
        MergeSubscribeInfoLocked(iter->second.subscribeInfos, subscribeInfos);
        iter->second.profileEvents |= subProfileEvents;
    } else {
        SubscribeRecord record {subscribeInfos, notifier, subProfileEvents};
        subscribeRecords_.emplace(eventCb, std::move(record));
    }
    return errCode;
}

int32_t DistributedDeviceProfileClient::UnsubscribeProfileEvent(ProfileEvent profileEvent,
    const std::shared_ptr<IProfileEventCallback>& eventCb)
{
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(profileEvent);
    std::list<ProfileEvent> failedEvents;
    return UnsubscribeProfileEvents(profileEvents, eventCb, failedEvents);
}

int32_t DistributedDeviceProfileClient::UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
    const std::shared_ptr<IProfileEventCallback>& eventCb,
    std::list<ProfileEvent>& failedEvents)
{
    if (profileEvents.empty() || eventCb == nullptr) {
        return ERR_DP_INVALID_PARAMS;
    }

    std::unique_lock<std::mutex> autoLock(subscribeLock_);
    ProfileEvents unsubProfileEvents;
    for (auto profileEvent : profileEvents) {
        unsubProfileEvents.set(static_cast<uint32_t>(profileEvent));
    }
    auto iter = subscribeRecords_.find(eventCb);
    if (iter == subscribeRecords_.end()) {
        return ERR_DP_NOT_SUBSCRIBED;
    }
    sptr<IRemoteObject> notifier = iter->second.notifier;
    autoLock.unlock();

    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }

    failedEvents.clear();
    int32_t errCode = dps->UnsubscribeProfileEvents(profileEvents, notifier, failedEvents);
    autoLock.lock();
    iter = subscribeRecords_.find(eventCb);
    if (iter != subscribeRecords_.end()) {
        for (auto failedEvent : failedEvents) {
            unsubProfileEvents.reset(static_cast<uint32_t>(failedEvent));
        }
        auto& subProfileEvents = iter->second.profileEvents;
        subProfileEvents &= ~unsubProfileEvents;
        if (subProfileEvents.none()) {
            subscribeRecords_.erase(iter);
        }
    }
    return errCode;
}

int32_t DistributedDeviceProfileClient::SyncDeviceProfile(const SyncOptions& syncOptions,
    const std::shared_ptr<IProfileEventCallback>& syncCb)
{
    auto dps = GetDeviceProfileService();
    if (dps == nullptr) {
        return ERR_DP_GET_SERVICE_FAILED;
    }

    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    return dps->SyncDeviceProfile(syncOptions, notifier);
}

sptr<IDistributedDeviceProfile> DistributedDeviceProfileClient::GetDeviceProfileService()
{
    std::lock_guard<std::mutex> lock(serviceLock_);
    if (dpProxy_ != nullptr) {
        return dpProxy_;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return nullptr;
    }
    auto object = samgrProxy->GetSystemAbility(DISTRIBUTED_DEVICE_PROFILE_SA_ID);
    if (object == nullptr) {
        HILOGE("get service failed");
        return nullptr;
    }
    HILOGI("get service succeeded");
    if (dpDeathRecipient_ == nullptr) {
        dpDeathRecipient_ = sptr<IRemoteObject::DeathRecipient>(
            new DeviceProfileDeathRecipient);
    }
    object->AddDeathRecipient(dpDeathRecipient_);
    dpProxy_ = iface_cast<IDistributedDeviceProfile>(object);
    return dpProxy_;
}

bool DistributedDeviceProfileClient::CheckProfileInvalidity(const ServiceCharacteristicProfile& profile)
{
    return profile.GetServiceId().empty() ||
           profile.GetServiceType().empty() ||
           profile.GetCharacteristicProfileJson().empty() ||
           profile.GetCharacteristicProfileJson() == JSON_NULL;
}

void DistributedDeviceProfileClient::MergeSubscribeInfoLocked(std::list<SubscribeInfo>& subscribeInfos,
    const std::list<SubscribeInfo>& newSubscribeInfos)
{
    for (const auto& newSubscribeInfo : newSubscribeInfos) {
        auto iter = std::find_if(subscribeInfos.begin(), subscribeInfos.end(),
            [&newSubscribeInfo](const auto& subscribeInfo) {
            return subscribeInfo.profileEvent == newSubscribeInfo.profileEvent;
        });
        if (iter == subscribeInfos.end()) {
            subscribeInfos.emplace_back(newSubscribeInfo);
            continue;
        }
        // override with the new subscribe info for same profile event
        *iter = newSubscribeInfo;
    }
}

void DistributedDeviceProfileClient::OnServiceDied(const sptr<IRemoteObject>& remote)
{
    HILOGI("called");
    {
        std::lock_guard<std::mutex> lock(serviceLock_);
        dpProxy_ = nullptr;
    }

    std::lock_guard<std::mutex> lock(subscribeLock_);
    if (dpClientHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("dpclient" + std::to_string(getpid()));
        dpClientHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }

    // try resubscribe when device profile service died
    auto resubscribe = [this]() {
        int32_t retryTimes = 0;
        sptr<IDistributedDeviceProfile> dps;
        do {
            std::this_thread::sleep_for(500ms);
            dps = GetDeviceProfileService();
            if (dps != nullptr) {
                HILOGI("get service succeeded");
                break;
            }
            if (retryTimes++ == RETRY_TIMES_GET_SERVICE) {
                HILOGE("get service timeout");
                return;
            }
        } while (true);

        std::list<ProfileEvent> failedEvents;
        std::lock_guard<std::mutex> lock(subscribeLock_);
        for (const auto& [_, subscribeRecord] : subscribeRecords_) {
            int32_t errCode = dps->SubscribeProfileEvents(subscribeRecord.subscribeInfos,
                subscribeRecord.notifier, failedEvents);
            HILOGI("resubscribe result = %{public}d", errCode);
        }
    };
    if (dpClientHandler_ != nullptr && !dpClientHandler_->PostTask(resubscribe)) {
        HILOGE("post task failed");
    }
}

void DistributedDeviceProfileClient::DeviceProfileDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    DistributedDeviceProfileClient::GetInstance().OnServiceDied(remote.promote());
}
} // namespace DeviceProfile
} // namespace OHOS
