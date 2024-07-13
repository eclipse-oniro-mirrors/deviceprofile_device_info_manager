/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_SYNC_COMPLETED_LISTENER_H
#define OHOS_DP_SYNC_COMPLETED_LISTENER_H

#include <map>
#include <memory>
#include <mutex>
#include "distributed_device_profile_enums.h"
#include "kvstore_sync_callback.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using SyncResults = std::map<std::string, SyncStatus>;
class KvSyncCompletedListener : public DistributedKv::KvStoreSyncCallback {
public:
    KvSyncCompletedListener(const std::string& storeId);
    ~KvSyncCompletedListener();

    void SyncCompleted(const std::map<std::string, DistributedKv::Status>& results) override;

private:
    void NotifySyncCompleted(const SyncResults& syncResults);

private:
    std::shared_ptr<AppExecFwk::EventHandler> onSyncHandler_ = nullptr;
    std::mutex reInitMutex_;
    std::string storeId_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SYNC_COMPLETED_LISTENER_H
