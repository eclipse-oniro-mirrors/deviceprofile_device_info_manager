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

#include "business_event_manager.h"

#include "business_event.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "kv_data_change_listener.h"
#include "kv_store_death_recipient.h"
#include "kv_sync_completed_listener.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(BusinessEventManager)

namespace {
    const std::string DP_REJECT_KEY = "business_id_cast+_reject_event";
    const std::string DP_DISTURBANCE_KEY = "business_id_cast+_disturbance_event";
    const std::string STORE_ID = "dp_kv_store_business";
    const std::string TAG = "BusinessEventManager";
    const std::set<std::string> validKeys_ = { DP_REJECT_KEY, DP_DISTURBANCE_KEY };
}

int32_t BusinessEventManager::Init()
{
    HILOGI("call!");
    std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
    businessEventAdapter_ = std::make_shared<BusinessEventAdapter>(
        std::make_shared<KvDeathRecipient>(STORE_ID), DistributedKv::TYPE_DYNAMICAL);
    int32_t ret = businessEventAdapter_->Init();
    if (ret != DP_SUCCESS) {
        HILOGE("businessEventAdapter init failed, ret: %{public}d", ret);
        return DP_INIT_DB_FAILED;
    }
    HILOGI("Init finish, ret: %{public}d", ret);
    return DP_SUCCESS;
}

int32_t BusinessEventManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (businessEventAdapter_ == nullptr) {
            HILOGE("businessEventAdapter_ is nullptr");
            return DP_KV_DB_PTR_NULL;
        }
        businessEventAdapter_->UnInit();
        businessEventAdapter_ = nullptr;
    }
    HILOGI("UnInit success");
    return DP_SUCCESS;
}

int32_t BusinessEventManager::PutBusinessEvent(const BusinessEvent& event)
{
    if (event.GetBusinessKey().empty() || event.GetBusinessValue().empty()) {
        HILOGE("Invalid parameter: Key or Value is empty.");
        return DP_INVALID_PARAM;
    }
    if (!IsValidKey(event.GetBusinessKey())) {
        HILOGE("Invalid BusinessKey: %{public}s", event.GetBusinessKey().c_str());
        return DP_INVALID_PARAM;
    }

    std::string key = event.GetBusinessKey();
    std::string value = event.GetBusinessValue();
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (businessEventAdapter_ == nullptr) {
            HILOGE("businessEventAdapter_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t ret = businessEventAdapter_->Put(key, value);
        if (ret != DP_SUCCESS) {
            HILOGE("Failed to insert business event with key: %{public}s", key.c_str());
            return DP_PUT_BUSINESS_EVENT_FAIL;
        }
    }
    HILOGI("PutBusinessEvent success for key: %{public}s", key.c_str());
    return DP_SUCCESS;
}

int32_t BusinessEventManager::GetBusinessEvent(BusinessEvent& event)
{
    if (event.GetBusinessKey().empty()) {
        HILOGE("Invalid parameter: BusinessKey is empty");
        return DP_INVALID_PARAM;
    }
    if (!IsValidKey(event.GetBusinessKey())) {
        HILOGE("Invalid BusinessKey: %{public}s", event.GetBusinessKey().c_str());
        return DP_INVALID_PARAM;
    }

    std::string key = event.GetBusinessKey();
    std::string value;
    {
        std::lock_guard<std::mutex> lock(dynamicStoreMutex_);
        if (businessEventAdapter_ == nullptr) {
            HILOGE("businessEventAdapter_ is null");
            return DP_KV_DB_PTR_NULL;
        }
        int32_t ret = businessEventAdapter_->Get(key, value);
        if (ret != DP_SUCCESS) {
            HILOGE("Failed to get business event with key: %{public}s", key.c_str());
            return DP_GET_BUSINESS_EVENT_FAIL;
        }
        event.SetBusinessValue(value);
    }
    HILOGI("GetBusinessEvent success for key: %{public}s", key.c_str());
    return DP_SUCCESS;
}

bool BusinessEventManager::IsValidKey(const std::string& key)
{
    return validKeys_.find(key) != validKeys_.end();
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
