/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_BUSINESS_EVENT_MANAGER_H
#define OHOS_DP_BUSINESS_EVENT_MANAGER_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "business_event.h"
#include "business_event_adapter.h"
#include "distributed_device_profile_constants.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class BusinessEventManager {
DECLARE_SINGLE_INSTANCE(BusinessEventManager);
public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutBusinessEvent(const BusinessEvent& event);
    int32_t GetBusinessEvent(BusinessEvent& event);
private:
    bool IsValidKey(const std::string& key);

private:
    std::shared_ptr<BusinessEventAdapter> businessEventAdapter_ = nullptr;
    std::mutex dynamicStoreMutex_;
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_BUSINESS_EVENT_MANAGER_H
 