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

#ifndef OHOS_DP_DEVICE_PROFILE_MANAGER_H
#define OHOS_DP_DEVICE_PROFILE_MANAGER_H

#include "single_instance.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "sync_options.h"
#include "iremote_object.h"
#include "i_sync_completed_callback.h"
#include "ikv_adapter.h"
#include "kv_data_change_listener.h"
#include "kv_sync_completed_listener.h"
#include "kv_store_death_recipient.h"
#include "i_dp_sync_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceProfileManager {
DECLARE_SINGLE_INSTANCE(DeviceProfileManager);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t ReInit();
    int32_t PutDeviceProfile(const DeviceProfile& deviceProfile);
    int32_t PutServiceProfile(const ServiceProfile& serviceProfile);
    int32_t PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles);
    int32_t PutCharacteristicProfile(const CharacteristicProfile& charProfile);
    int32_t PutCharacteristicProfileBatch(const std::vector<CharacteristicProfile>& charProfiles);
    int32_t GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile);
    int32_t GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
        ServiceProfile& serviceProfile);
    int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, CharacteristicProfile& charProfile);
    int32_t DeleteServiceProfile(const std::string& deviceId, const std::string& serviceName);
    int32_t DeleteCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey);
    int32_t GetAllDeviceProfile(std::vector<DeviceProfile>& deviceProfiles);
    int32_t GetAllServiceProfile(std::vector<ServiceProfile>& serviceProfiles);
    int32_t GetAllCharacteristicProfile(std::vector<CharacteristicProfile>& charProfiles);
    int32_t SyncDeviceProfile(const SyncOptions& syncOptions, sptr<IRemoteObject> syncCompletedCallback);

private:
    bool LoadDpSyncAdapter();
    void UnloadDpSyncAdapter();
    int32_t RunloadedFunction(std::string deviceId, sptr<IRemoteObject> syncCompletedCallbac);
    bool isAdapterSoLoaded_ = false;
    std::mutex isAdapterLoadLock_;
    std::mutex dpStoreMutex_;
    std::mutex dpSyncMutex_;
    // sptr<ISyncCompletedCallback> syncProfileCallback_;
    std::shared_ptr<IKVAdapter> deviceProfileStore_ = nullptr;
    std::shared_ptr<IDPSyncAdapter> dpSyncAdapter_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_MANAGER_H
