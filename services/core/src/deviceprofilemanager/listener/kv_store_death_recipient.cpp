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

#include "listener/kv_store_death_recipient.h"

#include "device_profile_manager.h"
#include "event_handler_factory.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvStoreDeathRecipient";
    const std::string REINIT_TASK = "reInitTask";
}

KvDeathRecipient::KvDeathRecipient()
{
    HILOGI("construct!");
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        reInitHandler_ = EventHandlerFactory::GetInstance().GetEventHandler();
    }
}

KvDeathRecipient::~KvDeathRecipient()
{
    HILOGI("destruct!");
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        if (reInitHandler_ == nullptr) {
            HILOGE("reInitHandler is nullptr!");
            return;
        }
        reInitHandler_->RemoveTask(REINIT_TASK);
        reInitHandler_ = nullptr;
    }
}

void KvDeathRecipient::OnRemoteDied()
{
    HILOGI("OnRemoteDied, recover db begin");
    auto reInitTask = []() {
        // how to recover kv_store
        DeviceProfileManager::GetInstance().ReInit();
    };
    {
        std::lock_guard<std::mutex> lock(reInitMutex_);
        if (reInitHandler_ == nullptr) {
            HILOGE("Create EventHandler is nullptr");
            return;
        }
        if (!reInitHandler_->PostTask(reInitTask, REINIT_TASK, 0)) {
            HILOGE("Post reInitTask fail!");
            return;
        }
    }
    HILOGI("OnRemoteDied, recover db end");
}
} // namespace DeviceProfile
} // namespace OHOS
