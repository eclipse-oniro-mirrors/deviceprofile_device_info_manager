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

#include "listener/kv_data_change_listener.h"

#include <cinttypes>

#include "datetime_ex.h"
#include "string_ex.h"

#include "profile_utils.h"
#include "profile_cache.h"
#include "subscribe_profile_manager.h"
#include "subscribe_profile_manager.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvDataChangeListener";
}

KvDataChangeListener::KvDataChangeListener()
{
    HILOGI("construct!");
}

KvDataChangeListener::~KvDataChangeListener()
{
    HILOGI("destruct!");
}

void KvDataChangeListener::OnChange(const DistributedKv::ChangeNotification& changeNotification)
{
    HILOGI("KvDataChangeListener: DB data OnChange");
    if (!changeNotification.GetInsertEntries().empty() &&
        changeNotification.GetInsertEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleAddChange(changeNotification.GetInsertEntries());
    }
    if (!changeNotification.GetUpdateEntries().empty() &&
        changeNotification.GetUpdateEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleUpdateChange(changeNotification.GetUpdateEntries());
    }
    if (!changeNotification.GetDeleteEntries().empty() &&
        changeNotification.GetDeleteEntries().size() <= MAX_DB_RECORD_SIZE) {
        HandleDeleteChange(changeNotification.GetDeleteEntries());
    }
}

void KvDataChangeListener::HandleAddChange(const std::vector<DistributedKv::Entry>& insertRecords)
{
    HILOGI("Handle kv data add change!");
    for (const auto& item : insertRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::ADD, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleUpdateChange(const std::vector<DistributedKv::Entry>& updateRecords)
{
    HILOGI("Handle kv data update change!");
    for (const auto& item : updateRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::UPDATE, dbKey, dbValue);
    }
}

void KvDataChangeListener::HandleDeleteChange(const std::vector<DistributedKv::Entry>& deleteRecords)
{
    HILOGI("Handle kv data delete change!");
    for (const auto& item : deleteRecords) {
        std::string dbKey = item.key.ToString();
        std::string dbValue = item.value.ToString();
        ProfileType profileType = ProfileUtils::GetProfileType(dbKey);
        SubscribeProfileManager::GetInstance().NotifyProfileChange(profileType, ChangeType::DELETE, dbKey, dbValue);
    }
}
} // namespace DeviceProfile
} // namespace OHOS