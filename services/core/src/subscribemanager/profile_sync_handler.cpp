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

#include "profile_sync_handler.h"

#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "device_profile_utils.h"
#include "subscribe_manager.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "ProfileSyncHandler";
}

void ProfileSyncHandler::SyncCompleted(const std::map<std::string, Status>& results)
{
    HILOGI("called");
    SyncResult syncResults;
    for (const auto& [deviceId, status] : results) {
        HILOGD("deviceId = %{public}s, status = %{public}d",
            DeviceProfileUtils::AnonymizeDeviceId(deviceId).c_str(), status);
        SyncStatus syncStauts = (status == Status::SUCCESS) ? SUCCEEDED : FAILED;
        syncResults.emplace(deviceId, syncStauts);
    }

    auto notifyTask = [this, syncResults = std::move(syncResults)]() {
        NotifySyncCompleted(syncResults);
    };
    std::lock_guard<std::mutex> autoLock(notifierLock_);
    if (eventHandler_ != nullptr && !eventHandler_->PostTask(notifyTask)) {
        HILOGI("post task failed");
    }
}

void ProfileSyncHandler::NotifySyncCompleted(const SyncResult& syncResults)
{
    {
        std::lock_guard<std::mutex> autoLock(notifierLock_);
        for (const auto& [notifier, _] : profileEventSubscribeInfos_) {
            sptr<IProfileEventNotifier> profileEventNotifier = iface_cast<IProfileEventNotifier>(notifier);
            if (profileEventNotifier == nullptr) {
                HILOGE("cast to IProfileEventNotifier failed");
                continue;
            }
            profileEventNotifier->OnSyncCompleted(syncResults);
        }
    }
    DeviceProfileStorageManager::GetInstance().NotifySyncCompleted();
}

int32_t ProfileSyncHandler::Register()
{
    HILOGI("called");
    return DeviceProfileStorageManager::GetInstance().RegisterSyncCallback(shared_from_this());
}

int32_t ProfileSyncHandler::Unregister()
{
    HILOGI("called");
    return DeviceProfileStorageManager::GetInstance().UnRegisterSyncCallback();
}
} // namespace DeviceProfile
} // namespace OHOS
