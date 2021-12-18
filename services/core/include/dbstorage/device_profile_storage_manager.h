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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H

#include <atomic>
#include <map>

#include "device_profile_storage.h"
#include "event_handler.h"
#include "kvstore_death_recipient.h"
#include "online_sync_table.h"
#include "service_characteristic_profile.h"
#include "single_instance.h"

#include "nlohmann/json.hpp"

namespace OHOS {
namespace DeviceProfile {
enum KeyType {
    UNKNOWN = -1,
    SERVICE = 0,
    SERVICE_LIST = 1,
    DEVICE_INFO = 2
};

class DeviceProfileStorageManager {
    DECLARE_SINGLE_INSTANCE(DeviceProfileStorageManager);

public:
    bool Init();
    void OnKvStoreInitDone();

    int32_t PutDeviceProfile(const ServiceCharacteristicProfile& profile);
    int32_t GetDeviceProfile(const std::string& udid, const std::string& serviceId,
        ServiceCharacteristicProfile& profile);

private:
    bool WaitKvDataService();
    void RestoreServiceItemLocked(const std::string& value);
    void FlushProfileItems();
    std::string GenerateKey(const std::string& udid, const std::string& key, KeyType keyType);

    void SetServiceType(const std::string& udid, const std::string& serviceId, ServiceCharacteristicProfile& profile);

private:
    std::mutex serviceLock_;
    nlohmann::json servicesJson_;
    std::unique_ptr<DeviceProfileStorage> onlineSyncTbl_;
    std::shared_ptr<AppExecFwk::EventHandler> storageHandler_;
    sptr<IRemoteObject::DeathRecipient> kvStoreDeathRecipient_;
    std::string localUdid_;
    std::map<std::string, std::string> profileItems_;
    std::atomic<bool> kvDataServiceFailed_ {false};
    std::atomic<bool> inited_ {false};
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_STORAGE_MANAGER_H