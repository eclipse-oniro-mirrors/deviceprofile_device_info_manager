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

#include "dp_client_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

#include "distributed_device_profile_client.h"
#include "profile_event.h"
#include "subscribe_info.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
constexpr int32_t TEST_LEVEL = 8;
constexpr uint32_t DP_EVENT_SIZE = 4;
constexpr uint32_t DP_SYNCMODE_SIZE = 3;
constexpr int32_t SUBSCRIBE_SLEEP_TIME = 120;
constexpr ProfileEvent profileEventFuzz[DP_EVENT_SIZE] = {
    ProfileEvent::EVENT_UNKNOWN, ProfileEvent::EVENT_SYNC_COMPLETED,
    ProfileEvent::EVENT_PROFILE_CHANGED, ProfileEvent::EVENT_PROFILE_END
};

constexpr SyncMode syncModeFuzz [DP_SYNCMODE_SIZE] {
    SyncMode::PULL, SyncMode::PUSH, SyncMode::PUSH_PULL
};
}

void FuzzPutDeviceProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ServiceCharacteristicProfile profile;
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceType(reinterpret_cast<const char*>(data), size);

    profile.SetServiceId(serviceId);
    profile.SetServiceType(serviceType);
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = TEST_LEVEL;
    profile.SetCharacteristicProfileJson(j.dump());
    DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
}

void FuzzGetDeviceProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ServiceCharacteristicProfile profile;
    std::string udid(reinterpret_cast<const char*>(data), size);
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(udid, serviceId, profile);
}

void FuzzDeleteDeviceProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string serviceId(reinterpret_cast<const char*>(data), size);
    DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile(serviceId);
}

void FuzzSubscribeProfileEvents(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto callback = std::make_shared<IProfileEventCallback>();
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceIds(reinterpret_cast<const char*>(data), size);
    std::list<SubscribeInfo> subscribeInfos;
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;
    SubscribeInfo info1;
    info1.profileEvent = profileEventFuzz[data[0] % DP_EVENT_SIZE];
    info1.extraInfo = std::move(extraInfo);
    subscribeInfos.emplace_back(info1);
    std::list<ProfileEvent> failedEvents;
    DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvents(subscribeInfos, callback, failedEvents);

    sleep(SUBSCRIBE_SLEEP_TIME);
    std::list<ProfileEvent> profileEvents;
    profileEvents.emplace_back(profileEventFuzz[data[0] % DP_EVENT_SIZE]);
    failedEvents.clear();
    DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvents(profileEvents, callback, failedEvents);
}

void FuzzSyncDeviceProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto syncCb = std::make_shared<IProfileEventCallback>();
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    SyncOptions syncOption;
    syncOption.SetSyncMode(syncModeFuzz[data[0] % DP_SYNCMODE_SIZE]);
    syncOption.AddDevice(deviceId);
    DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOption, syncCb);
}

void FuzzSubscribeProfileEvent(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto callback = std::make_shared<IProfileEventCallback>();
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string serviceIds(reinterpret_cast<const char*>(data), size);
    ExtraInfo extraInfo;
    extraInfo["deviceId"] = deviceId;
    extraInfo["serviceIds"] = serviceIds;

    SubscribeInfo subscribeInfo;
    subscribeInfo.profileEvent = profileEventFuzz[data[0] % DP_EVENT_SIZE];
    subscribeInfo.extraInfo = std::move(extraInfo);
    DistributedDeviceProfileClient::GetInstance().SubscribeProfileEvent(subscribeInfo, callback);

    ProfileEvent profileEvent = profileEventFuzz[data[0] % DP_EVENT_SIZE];
    DistributedDeviceProfileClient::GetInstance().UnsubscribeProfileEvent(profileEvent, callback);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::FuzzPutDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzGetDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzDeleteDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzSubscribeProfileEvents(data, size);
    OHOS::DeviceProfile::FuzzSyncDeviceProfile(data, size);
    OHOS::DeviceProfile::FuzzSubscribeProfileEvent(data, size);
    return 0;
}