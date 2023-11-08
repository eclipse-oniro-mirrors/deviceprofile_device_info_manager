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
#include "sync_subscriber_death_recipient.h"

#include "distributed_device_profile_log.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "KvStoreDeathRecipient";
}

SyncSubscriberDeathRecipient::SyncSubscriberDeathRecipient()
{
    HILOGI("construct!");
}

SyncSubscriberDeathRecipient::~SyncSubscriberDeathRecipient()
{
    HILOGI("destruct!");
}

void SyncSubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    HILOGI("called");
    if (remote == nullptr || remote->GetObjectDescriptor().size() == 0 ||
        remote->GetObjectDescriptor().size() > MAX_STRING_LEN) {
        HILOGE("Param is invalid");
        return;
    }
    ProfileCache::GetInstance().RemoveSyncListener(remote->GetObjectDescriptor());
}
} // namespace DeviceProfile
} // namespace OHOS