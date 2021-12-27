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

#ifndef OHOS_DISTRIBUTED_PROFILE_SYNC_COORDINATOR_H
#define OHOS_DISTRIBUTED_PROFILE_SYNC_COORDINATOR_H

#include <atomic>
#include <functional>

#include "single_instance.h"

#include "event_handler.h"

namespace OHOS {
namespace DeviceProfile {
class SyncCoordinator {
    DECLARE_SINGLE_INSTANCE(SyncCoordinator);
public:
    using SyncTask = std::function<void()>;

    bool Init();
    bool AcquireSync();
    void ReleaseSync();
    void SetSyncTrigger(bool isOnlineTrigger);
    bool IsOnlineSync();
    bool DispatchSyncTask(const SyncTask& syncTask, int64_t delayTime = 0);

private:
    std::atomic<bool> isOnlineTrigger_ {false};
    std::atomic<bool> isOnSync_ {false};
    std::shared_ptr<AppExecFwk::EventHandler> syncHandler_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_PROFILE_SYNC_COORDINATOR_H