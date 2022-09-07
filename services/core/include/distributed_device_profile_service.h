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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H

#include "distributed_device_profile_stub.h"
#include "single_instance.h"

#include "system_ability.h"

namespace OHOS {
namespace DeviceProfile {
class DistributedDeviceProfileService : public SystemAbility, public DistributedDeviceProfileStub {
    DECLARE_SYSTEM_ABILITY(DistributedDeviceProfileService);
    DECLARE_SINGLE_INSTANCE_BASE(DistributedDeviceProfileService);

public:
    DistributedDeviceProfileService();
    ~DistributedDeviceProfileService() = default;

    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile) override;
    int32_t DeleteDeviceProfile(const std::string& serviceId) override;
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile) override;
    int32_t SubscribeProfileEvents(const std::list<SubscribeInfo>& subscribeInfos,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) override;
    int32_t UnsubscribeProfileEvents(const std::list<ProfileEvent>& profileEvents,
        const sptr<IRemoteObject>& profileEventNotifier,
        std::list<ProfileEvent>& failedEvents) override;
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions,
        const sptr<IRemoteObject>& profileEventNotifier) override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    bool Init();
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_SERVICE_H