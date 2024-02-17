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

#include "event_handler_factory.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(EventHandlerFactory);

namespace {
    const std::string TAG = "EventHandlerFactory";
}

int32_t EventHandlerFactory::Init()
{
    HILOGI("call!");
    auto unloadRunner = AppExecFwk::EventRunner::Create(UNLOAD_DP_SA_HANDLER);
    eventHandlerMap_[UNLOAD_DP_SA_HANDLER] = std::make_shared<AppExecFwk::EventHandler>(unloadRunner);
    auto kvDeathRunner = AppExecFwk::EventRunner::Create(KV_DEATH_HANDLER);
    eventHandlerMap_[KV_DEATH_HANDLER] = std::make_shared<AppExecFwk::EventHandler>(kvDeathRunner);
    auto onSyncRunner = AppExecFwk::EventRunner::Create(ON_SYNC_HANDLER);
    eventHandlerMap_[ON_SYNC_HANDLER] = std::make_shared<AppExecFwk::EventHandler>(onSyncRunner);
    auto autoSyncRunner = AppExecFwk::EventRunner::Create(AUTO_SYNC_HANDLER);
    eventHandlerMap_[AUTO_SYNC_HANDLER] = std::make_shared<AppExecFwk::EventHandler>(autoSyncRunner);
    return DP_SUCCESS;
}

int32_t EventHandlerFactory::UnInit()
{
    HILOGI("UnInit");
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    eventHandlerMap_.clear();
    return DP_SUCCESS;
}

std::shared_ptr<AppExecFwk::EventHandler> EventHandlerFactory::CreateEventHandler(const std::string& handlerName)
{
    if (handlerName.empty() || handlerName.size() > MAX_STRING_LEN) {
        HILOGI("handlerName is invalid!");
        return nullptr;
    }
    HILOGI("createEventHandler, handlerName: %s", handlerName.c_str());
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    return eventHandlerMap_[handlerName];
}
} // namespace DeviceProfile
} // namespace OHOS