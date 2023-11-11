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

#include "content_sensor_manager.h"

#include <list>
#include <string>
#include <memory>
#include "device_info_collector.h"
#include "distributed_device_profile_log.h"
#include "storage_info_collector.h"
#include "syscap_info_collector.h"
#include "system_info_collector.h"
#include "distributed_device_profile_errors.h"
#include "device_profile.h"
#include "event_handler.h"
#include "collector.h"
#include "device_profile_manager.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ContentSensorManager";
    const std::string DP_CONTENT_SENSOR_TRACE = "DP_CONTENT_SENSOR";
}

IMPLEMENT_SINGLE_INSTANCE(ContentSensorManager);

int32_t ContentSensorManager::Init()
{
    auto runner = AppExecFwk::EventRunner::Create("csCollector");
    csCollectorHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    if (csCollectorHandler_ == nullptr) {
        return DP_CS_COLLECTOR_HANDLER_INIT_FAIL;
    }
    return Collect();
}

int32_t ContentSensorManager::UnInit()
{
    HILOGI("ContentSensorManager UnInit");
    return DP_SUCCESS;
}

int32_t ContentSensorManager::Collect()
{
    auto csTask = []() {
        HILOGI("ContentSensorManager Collect");
        std::list<std::shared_ptr<Collector>> taskList;
        taskList.push_back(std::make_shared<DeviceInfoCollector>());
        taskList.push_back(std::make_shared<SystemInfoCollector>());
        taskList.push_back(std::make_shared<SyscapInfoCollector>());
        taskList.push_back(std::make_shared<StorageInfoCollector>());
        DeviceProfile deviceProfile;
        for (const auto& task : taskList) {
            if (!task->ConvertToProfile(deviceProfile)) {
                continue;
            }
        }
        DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    };
    if (!csCollectorHandler_->PostTask(csTask)) {
        HILOGE("post task failed");
        return DP_CS_POST_TASK_FAIL;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
