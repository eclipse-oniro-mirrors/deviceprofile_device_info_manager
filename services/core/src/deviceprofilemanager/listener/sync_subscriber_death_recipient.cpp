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

#include <string>
#include "listener/sync_subscriber_death_recipient.h"

#include "distributed_device_profile_log.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SyncSubscriberDeathRecipient";
}

SyncSubscriberDeathRecipient::SyncSubscriberDeathRecipient()
{
    HILOGD("construct!");
}

SyncSubscriberDeathRecipient::~SyncSubscriberDeathRecipient()
{
    HILOGD("destruct!");
}

void SyncSubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    HILOGD("called");
    if (remote == nullptr) {
        HILOGE("remote is nullptr!");
        return;
    }
    sptr<IRemoteObject> diedRemote = remote.promote();
    if (diedRemote == nullptr) {
        HILOGE("diedRemote is nullptr!");
        return;
    }
    ProfileCache::GetInstance().RemoveSyncListener(diedRemote);
}
} // namespace DeviceProfile
} // namespace OHOS
