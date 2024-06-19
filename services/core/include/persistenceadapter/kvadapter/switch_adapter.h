/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_SWITCH_ADAPTER_H
#define OHOS_DP_SWITCH_ADAPTER_H

#include <mutex>
#include <string>
#include <utility>

#include "distributed_kv_data_manager.h"
#include "kv_adapter.h"
#include "kvstore_observer.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SwitchAdapter {
DECLARE_SINGLE_INSTANCE(SwitchAdapter);

public:
    void Init();
    void Uninit();
    int32_t PutSwitch(const std::string& appId, uint32_t value, uint16_t length);
    int32_t GetSwitch(const std::string& appId, const std::string& networkId, uint32_t& value, uint32_t& switchLength);
    int32_t SubscribeSwitchData(const std::string& appId);
    int32_t UnsubscribeSwitchData(const std::string& appId);

private:
    std::shared_ptr<DistributedKv::KvStoreObserver> observer_;
    DistributedKv::DistributedKvDataManager kvDataMgr_;
    std::mutex switchAdapterMutex_;
};

} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SWITCH_ADAPTER_H
