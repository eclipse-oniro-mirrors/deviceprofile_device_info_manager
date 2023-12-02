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

#ifndef OHOS_DP_DEATH_LISTENER_H
#define OHOS_DP_DEATH_LISTENER_H

#include <memory>
#include <mutex>
#include "kvstore_death_recipient.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class KvDeathRecipient : public DistributedKv::KvStoreDeathRecipient {
public:
    KvDeathRecipient();
    virtual ~KvDeathRecipient();

    virtual void OnRemoteDied() override;

private:
    std::shared_ptr<AppExecFwk::EventHandler> reInitHandler_ = nullptr;
    std::mutex reInitMutex_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEATH_LISTENER_H