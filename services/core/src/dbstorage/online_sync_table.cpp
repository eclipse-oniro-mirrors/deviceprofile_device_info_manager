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

#include "online_sync_table.h"

#include "device_manager.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_utils.h"
#include "sync_coordinator.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "OnlineSyncTable";

const std::string APP_ID = "distributed_device_profile_service";
const std::string STORE_ID = "online_sync_storage";
constexpr int32_t MAX_RETRY_SYNC_TIMES = 10;
}

OnlineSyncTable::OnlineSyncTable() : DeviceProfileStorage(APP_ID, STORE_ID)
{
}

void OnlineSyncTable::Init()
{
    HILOGD("called");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
    };
    SetOptions(options);
    DeviceProfileStorage::Init();
    int32_t errCode = DeviceProfileStorage::RegisterSyncCallback(shared_from_this());
    if (errCode != ERR_OK) {
        HILOGE("register sync callback failed, errCode = %{public}d", errCode);
    }
}

int32_t OnlineSyncTable::RegisterSyncCallback(const std::shared_ptr<KvStoreSyncCallback>& syncCb)
{
    if (syncCb == nullptr) {
        return ERR_DP_INVALID_PARAMS;
    }
    std::lock_guard<std::mutex> autoLock(tableLock_);
    manualSyncCallback_ = syncCb;
    return ERR_OK;
}

int32_t  OnlineSyncTable::UnRegisterSyncCallback()
{
    std::lock_guard<std::mutex> autoLock(tableLock_);
    manualSyncCallback_ = nullptr;
    return ERR_OK;
}

int32_t OnlineSyncTable::SyncDeviceProfile(const std::vector<std::string>& deviceIds,
    DistributedKv::SyncMode syncMode)
{
    HILOGI("called");
    auto syncTask = [this, deviceIds = std::move(deviceIds), syncMode]() {
        HILOGI("start sync task");
        retrySyncTimes_ = 0;
        int32_t errCode = DeviceProfileStorage::SyncDeviceProfile(deviceIds, syncMode);
        if (errCode != ERR_OK) {
            SyncCoordinator::GetInstance().ReleaseSync();
            HILOGE("sync errCode = %{public}d", errCode);
        }
    };
    if (!SyncCoordinator::GetInstance().DispatchSyncTask(syncTask)) {
        HILOGE("post online sync task failed");
        return ERR_DP_POST_TASK_FAILED;
    }
    return ERR_OK;
}

void OnlineSyncTable::SyncCompleted(const std::map<std::string, Status>& results)
{
    if (!SyncCoordinator::GetInstance().IsOnlineSync()) {
        std::lock_guard<std::mutex> autoLock(tableLock_);
        if (manualSyncCallback_ != nullptr) {
            HILOGI("manual sync callback");
            manualSyncCallback_->SyncCompleted(results);
        }
        return;
    }

    HILOGI("online sync callback");
    std::vector<std::string> failedDeviceIds;
    for (const auto& [deviceId, result] : results) {
        HILOGI("deviceId = %{public}s, result = %{public}d",
            DeviceProfileUtils::AnonymizeDeviceId(deviceId).c_str(), result);
        if (result != Status::SUCCESS) {
            std::string networkId;
            if (!DeviceManager::GetInstance().TransformDeviceId(deviceId, networkId,
                DeviceIdType::NETWORKID)) {
                HILOGE("transform to networkid failed");
                continue;
            }
            failedDeviceIds.emplace_back(std::move(networkId));
        }
    }

    HILOGI("retry times = %{public}d", retrySyncTimes_.load());
    if ((retrySyncTimes_++ < MAX_RETRY_SYNC_TIMES) && !failedDeviceIds.empty()) {
        auto retrySyncTask = [this, deviceIds = std::move(failedDeviceIds)]() {
            HILOGI("retrying sync...");
            SyncDeviceProfile(deviceIds, SyncMode::PUSH);
        };
        if (!SyncCoordinator::GetInstance().DispatchSyncTask(retrySyncTask)) {
            HILOGE("post online sync retry task failed");
            return;
        }
    }
    SyncCoordinator::GetInstance().ReleaseSync();
}
} // namespace DeviceProfile
} // namespace OHOS