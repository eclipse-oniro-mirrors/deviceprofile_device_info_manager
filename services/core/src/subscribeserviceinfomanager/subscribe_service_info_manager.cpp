/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "subscribe_service_info_manager.h"
#include <thread>
#include "distributed_device_profile_errors.h"
#include "i_service_info_change_callback.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SubscribeServiceInfoManager);
namespace {
    const std::string TAG = "SubscribeServiceInfoManager";
}

int32_t SubscribeServiceInfoManager::Init()
{
    HILOGI("call!");
    return DP_SUCCESS;
}

int32_t SubscribeServiceInfoManager::UnInit()
{
    HILOGI("call!");
    {
        std::lock_guard<std::mutex> lockGuard(serviceInfoMutex_);
        serviceInfoMap_.clear();
    }
    return DP_SUCCESS;
}

int32_t SubscribeServiceInfoManager::NotifyServiceInfoAdd(const std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("NotifyServiceInfoAdd");
    {
        std::lock_guard<std::mutex> lockGuard(serviceInfoMutex_);
        for (const auto &[saId, listener] : serviceInfoMap_) {
            if (listener == nullptr) {
                HILOGE("Cast to IServiceInfoChangeCallback failed!");
                continue;
            }
            sptr<IServiceInfoChangeCallback> listenerProxy = iface_cast<IServiceInfoChangeCallback>(listener);

            if (listenerProxy != nullptr) {
                std::thread([listenerProxy, serviceInfos]() {
                    listenerProxy->OnServiceInfoInsert(serviceInfos);
                }).detach();
            }
        }
    }

    return DP_SUCCESS;
}

int32_t SubscribeServiceInfoManager::NotifyServiceInfoUpdate(const std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("NotifyServiceInfoUpdate");
    {
        std::lock_guard<std::mutex> lockGuard(serviceInfoMutex_);
        for (const auto &[saId, listener] : serviceInfoMap_) {
            if (listener == nullptr) {
                HILOGE("Cast to IServiceInfoChangeCallback failed!");
                continue;
            }
            sptr<IServiceInfoChangeCallback> listenerProxy = iface_cast<IServiceInfoChangeCallback>(listener);

            if (listenerProxy != nullptr) {
                std::thread([listenerProxy, serviceInfos]() {
                    listenerProxy->OnServiceInfoUpdate(serviceInfos);
                }).detach();
            }
        }
    }

    return DP_SUCCESS;
}

int32_t SubscribeServiceInfoManager::NotifyServiceInfoDelete(const std::vector<ServiceInfo>& serviceInfos)
{
    HILOGI("NotifyServiceInfoDelete");
    {
        std::lock_guard<std::mutex> lockGuard(serviceInfoMutex_);
        for (const auto &[saId, listener] : serviceInfoMap_) {
            if (listener == nullptr) {
                HILOGE("Cast to IServiceInfoChangeCallback failed!");
                continue;
            }
            sptr<IServiceInfoChangeCallback> listenerProxy = iface_cast<IServiceInfoChangeCallback>(listener);

            if (listenerProxy != nullptr) {
                std::thread([listenerProxy, serviceInfos]() {
                    listenerProxy->OnServiceInfoDelete(serviceInfos);
                }).detach();
            }
        }
    }
    return DP_SUCCESS;
}

int32_t SubscribeServiceInfoManager::SubscribeServiceInfo(int32_t saId, sptr<IRemoteObject> listener)
{
    HILOGI("SubscribeServiceInfo");
    {
        std::lock_guard<std::mutex> lock(serviceInfoMutex_);
        if (serviceInfoMap_.size() > MAX_LISTENER_SIZE) {
            HILOGE("ServiceInfoMap size is invalid!size: %{public}zu!", serviceInfoMap_.size());
            return DP_EXCEED_MAX_SIZE_FAIL;
        }

        auto iter = serviceInfoMap_.find(saId);
        if (iter != serviceInfoMap_.end()) {
            serviceInfoMap_.erase(iter);
        }

        serviceInfoMap_.emplace(saId, listener);
    }

    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS