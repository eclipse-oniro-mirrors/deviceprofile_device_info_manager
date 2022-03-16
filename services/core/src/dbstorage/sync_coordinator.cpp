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

#include "sync_coordinator.h"

#include <string>

#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SyncCoordinator";
}

IMPLEMENT_SINGLE_INSTANCE(SyncCoordinator);

bool SyncCoordinator::Init()
{
    auto runner = AppExecFwk::EventRunner::Create("syncHandler");
    syncHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    if (syncHandler_ == nullptr) {
        return false;
    }
    return true;
}

bool SyncCoordinator::AcquireSync()
{
    if (isOnSync_) {
        HILOGI("acquire from %{public}s", isOnlineTrigger_ ? "online" : "manual");
        return false;
    }
    isOnSync_ = true;
    return true;
}

void SyncCoordinator::ReleaseSync()
{
    isOnSync_ = false;
}

void SyncCoordinator::SetSyncTrigger(bool isOnlineTrigger)
{
    isOnlineTrigger_ = isOnlineTrigger;
}

bool SyncCoordinator::IsOnlineSync()
{
    return isOnlineTrigger_;
}

bool SyncCoordinator::DispatchSyncTask(const SyncTask& syncTask, int64_t delayTime)
{
    if (!syncHandler_->PostTask(syncTask, delayTime)) {
        HILOGE("post task failed");
        isOnSync_ = false;
        return false;
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS
