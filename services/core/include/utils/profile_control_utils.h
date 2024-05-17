/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_PROFILE_CONTROLLER_H
#define OHOS_DP_PROFILE_CONTROLLER_H

#include <unordered_map>
#include "single_instance.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "dp_sync_options.h"
#include "iremote_object.h"
#include "i_sync_completed_callback.h"
#include "ikv_adapter.h"
#include "common/kv_data_change_listener.h"
#include "common/kv_sync_completed_listener.h"
#include "common/kv_store_death_recipient.h"
#include "i_dp_sync_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProfileControlUtils {
public:
    static int32_t PutDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const DeviceProfile& deviceProfile);
    static int32_t PutServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const ServiceProfile& serviceProfile);
    static int32_t PutServiceProfileBatch(std::shared_ptr<IKVAdapter> kvStore,
        const std::vector<ServiceProfile>& serviceProfiles);
    static int32_t PutCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
        const CharacteristicProfile& charProfile);
    static int32_t PutSwitchCharacteristicProfile(const std::string& appId,
        const CharacteristicProfile& charProfile); //写入开关数据
    static int32_t PutCharacteristicProfileBatch(std::shared_ptr<IKVAdapter> kvStore,
        const std::vector<CharacteristicProfile>& charProfiles);
    static int32_t PutSwitchCharacteristicProfileBatch(const std::string& appId,
        const std::vector<CharacteristicProfile>& charProfiles); //批量写入开关数据
    static int32_t GetDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
        DeviceProfile& deviceProfile);
    static int32_t GetServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
        const std::string& serviceName, ServiceProfile& serviceProfile);
    static int32_t GetCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
        const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile);
    static int32_t GetSwitchCharacteristicProfile(const std::string& appId, const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey, CharacteristicProfile& charProfile);
    static int32_t DeleteServiceProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
        const std::string& serviceName);
    static int32_t DeleteCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore, const std::string& deviceId,
        const std::string& serviceName, const std::string& characteristicKey);
    static int32_t GetAllDeviceProfile(std::shared_ptr<IKVAdapter> kvStore, std::vector<DeviceProfile>& deviceProfiles);
    static int32_t GetAllServiceProfile(std::shared_ptr<IKVAdapter> kvStore,
        std::vector<ServiceProfile>& serviceProfiles);
    static int32_t GetAllCharacteristicProfile(std::shared_ptr<IKVAdapter> kvStore,
        std::vector<CharacteristicProfile>& charProfiles);
    static int32_t RefreshLocalSwitchProfile(const std::string& appId);
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_MANAGER_H