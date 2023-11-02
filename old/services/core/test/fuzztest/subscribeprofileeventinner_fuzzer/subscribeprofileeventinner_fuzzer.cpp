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

#include "subscribeprofileeventinner_fuzzer.h"

#include "distributed_device_profile_stub.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileStubTest : public DistributedDeviceProfileStub {
public:
public:
    DistributedDeviceProfileStubTest() = default;
    ~DistributedDeviceProfileStubTest() = default;
    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile)
    {
        (void)profile;
        return 0;
    }
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile)
    {
        (void)udid;
        (void)serviceId;
        (void)profile;
        return 0;
    }
    int32_t DeleteDeviceProfile(const std::string& serviceId)
    {
        (void)serviceId;
        return 0;
    }
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)subscribeInfos;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier, std::list<ProfileEvent>& failedEvents)
    {
        (void)profileEvents;
        (void)profileEventNotifier;
        (void)failedEvents;
        return 0;
    }
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions, const sptr<IRemoteObject>& profileEventNotifier)
    {
        (void)syncOptions;
        (void)profileEventNotifier;
        return 0;
    }
};
void FuzzDumpLocalProfile(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    uint32_t numSubscribeInfos = *(reinterpret_cast<const uint32_t*>(data));
    MessageParcel messageData;
    MessageParcel reply;
    messageData.WriteUint32(numSubscribeInfos);
    std::shared_ptr<DistributedDeviceProfileStub> deviceProfileStub =
        std::make_shared<DistributedDeviceProfileStubTest>();
    deviceProfileStub->SubscribeProfileEventInner(messageData, reply);
    deviceProfileStub->UnsubscribeProfileEventInner(messageData, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::FuzzDumpLocalProfile(data, size);
    return 0;
}

