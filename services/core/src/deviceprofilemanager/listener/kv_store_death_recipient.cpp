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

#include "listener/kv_store_death_recipient.h"

#include "device_profile_manager.h"
#include "event_handler_factory.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "static_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvStoreDeathRecipient";
    const std::string REINIT_TASK = "reInitTask";
    const std::string DYNAMIC_STORE_ID = "dp_kv_store";
    const std::string STATIC_STORE_ID = "dp_kv_static_store";
}

KvDeathRecipient::KvDeathRecipient(const std::string& storeId)
{
    HILOGI("construct!");
    storeId_ = storeId;
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
    auto reInitTask = [this]() {
        HILOGI("ReInit, storeId:%{public}s", storeId_.c_str());
        if (storeId_ == DYNAMIC_STORE_ID) {
            DeviceProfileManager::GetInstance().ReInit();
        }
        if (storeId_ == STATIC_STORE_ID) {
            StaticProfileManager::GetInstance().ReInit();
        }
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
