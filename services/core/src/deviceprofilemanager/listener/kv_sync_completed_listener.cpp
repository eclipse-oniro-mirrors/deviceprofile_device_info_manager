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

#include "listener/kv_sync_completed_listener.h"

#include <cinttypes>

#include "datetime_ex.h"
#include "string_ex.h"

#include "distributed_device_profile_log.h"
#include "profile_utils.h"
#include "profile_cache.h"
#include "i_sync_completed_callback.h"
#include "event_handler_factory.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvSyncCompletedListener";
    const std::string ON_SYNC_TASK_ID = "on_sync_task";
}

KvSyncCompletedListener::KvSyncCompletedListener()
{
    HILOGI("construct!");
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        onSyncHandler_ = EventHandlerFactory::GetInstance().CreateEventHandler(ON_SYNC_HANDLER);
    }
}

KvSyncCompletedListener::~KvSyncCompletedListener()
{
    HILOGI("destruct!");
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        if (onSyncHandler_ == nullptr) {
            HILOGE("onSyncHandler is nullptr!");
            return;
        }
        onSyncHandler_->RemoveTask(ON_SYNC_TASK_ID);
        onSyncHandler_ = nullptr;
    }
}

void KvSyncCompletedListener::SyncCompleted(const std::map<std::string, DistributedKv::Status>& results)
{
    HILOGI("called!");

    ProfileCache::GetInstance().RefreshProfileCache();
    SyncResults syncResults;
    for (const auto& [deviceId, status] : results) {
        HILOGD("deviceId = %{public}s, status = %{public}d", ProfileUtils::GetAnonyString(deviceId).c_str(), status);
        SyncStatus syncStatus = (status == DistributedKv::Status::SUCCESS) ? SyncStatus::SUCCEEDED : SyncStatus::FAILED;
        syncResults.emplace(deviceId, syncStatus);
    }
    auto notifyTask = [this, syncResults = std::move(syncResults)]() {
        NotifySyncCompleted(syncResults);
    };
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        if (onSyncHandler_ == nullptr) {
            HILOGE("Create EventHandler is nullptr, handlerName: %s!", ON_SYNC_HANDLER.c_str());
            return;
        }
        if (!onSyncHandler_->PostTask(notifyTask, ON_SYNC_TASK_ID, 0)) {
            HILOGE("Post task fail!");
            return;
        }
    }
}

void KvSyncCompletedListener::NotifySyncCompleted(const SyncResults& syncResults)
{
    int64_t beginTime = GetTickCount();
    std::map<std::string, sptr<IRemoteObject>> syncListeners;
    ProfileCache::GetInstance().GetSyncListeners(syncListeners);
    for (const auto& [_, syncListenerStub] : syncListeners) {
        sptr<ISyncCompletedCallback> syncListenerProxy = iface_cast<ISyncCompletedCallback>(syncListenerStub);
        if (syncListenerProxy == nullptr) {
            HILOGE("Cast to ISyncCompletedCallback failed");
            continue;
        }
        syncListenerProxy->OnSyncCompleted(syncResults);
    }
    ProfileCache::GetInstance().RemoveSyncListeners(syncListeners);
    int64_t endTime = GetTickCount();
    HILOGI("NotifySyncCompleted, spend %{public}" PRId64 " ms", endTime - beginTime);
}
} // namespace DeviceProfile
} // namespace OHOS

