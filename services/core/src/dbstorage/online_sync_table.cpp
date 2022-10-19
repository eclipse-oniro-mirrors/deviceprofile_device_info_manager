/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_utils.h"
#include "dp_device_manager.h"
#include "sync_coordinator.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "OnlineSyncTable";

const std::string APP_ID = "distributed_device_profile_service";
const std::string STORE_ID = "online_sync_storage";
constexpr int32_t MAX_RETRY_SYNC_TIMES = 30;
constexpr int32_t INTERVAL_RETRY_SYNC_MS = 100;
}

OnlineSyncTable::OnlineSyncTable() : DeviceProfileStorage(APP_ID, STORE_ID)
{
}

void OnlineSyncTable::Init()
{
    HILOGD("called");
    Options options = {
        .createIfMissing = true,
        .encrypt = true,
        .autoSync = true,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .area = 1,
        .baseDir = "/data/service/el1/public/database/distributed_device_profile_service"
    };
    // clean the IMMEDIATE_SYNC_ON_CHANGE
    options.policies = {};
    SyncPolicy syncPolicy {
        .type = PolicyType::IMMEDIATE_SYNC_ON_ONLINE
    };
    options.policies.emplace_back(syncPolicy);
    SetOptions(options);
    DeviceProfileStorage::Init();
    int32_t errCode = DeviceProfileStorage::RegisterSyncCallback(shared_from_this());
    if (errCode != ERR_OK) {
        HILOGE("register sync callback failed, errCode = %{public}d", errCode);
    }
}

int32_t OnlineSyncTable::RegisterSyncCallback(const std::shared_ptr<KvStoreSyncCallback>& syncCb)
{
    HILOGI("called");
    if (syncCb == nullptr) {
        return ERR_DP_INVALID_PARAMS;
    }
    std::lock_guard<std::mutex> autoLock(tableLock_);
    syncCallback_ = syncCb;
    return ERR_OK;
}

int32_t  OnlineSyncTable::UnRegisterSyncCallback()
{
    HILOGI("called");
    std::lock_guard<std::mutex> autoLock(tableLock_);
    syncCallback_ = nullptr;
    return ERR_OK;
}

int32_t OnlineSyncTable::SyncDeviceProfile(const std::vector<std::string>& deviceIds,
    SyncMode syncMode)
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
        HILOGI("manual sync callback");
        NotifySyncCompleted(results);
        return;
    }

    HILOGI("online sync callback");
    std::vector<std::string> failedDeviceIds;
    for (const auto& [deviceId, result] : results) {
        HILOGI("deviceId = %{public}s, result = %{public}d",
            DeviceProfileUtils::AnonymizeDeviceId(deviceId).c_str(), result);
        if (result != Status::SUCCESS) {
            std::string networkId;
            if (!DpDeviceManager::GetInstance().TransformDeviceId(deviceId, networkId,
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
            DeviceProfileStorage::SyncDeviceProfile(deviceIds, SyncMode::PUSH);
        };
        if (SyncCoordinator::GetInstance().DispatchSyncTask(retrySyncTask,
            INTERVAL_RETRY_SYNC_MS)) {
            return;
        } else {
            HILOGE("post online sync retry task failed");
        }
    }
    // notify and release when there is no retry
    NotifySyncCompleted(results);
    SyncCoordinator::GetInstance().ReleaseSync();
}

void OnlineSyncTable::NotifySyncCompleted(const std::map<std::string, Status>& results)
{
    std::lock_guard<std::mutex> autoLock(tableLock_);
    if (syncCallback_ != nullptr) {
        HILOGI("notify sync callback");
        syncCallback_->SyncCompleted(results);
    }
}
} // namespace DeviceProfile
} // namespace OHOS