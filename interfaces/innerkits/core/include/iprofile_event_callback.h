/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_PROFILE_I_PROFILE_EVENT_CALLBACK_H
#define OHOS_DEVICE_PROFILE_I_PROFILE_EVENT_CALLBACK_H

#include <map>
#include "profile_change_notification.h"

namespace OHOS {
namespace DeviceProfile {
enum SyncStatus {
    SUCCEEDED = 0,
    FAILED = 1
};

using SyncResult = std::map<std::string, SyncStatus>;

class IProfileEventCallback {
public:
    IProfileEventCallback() = default;
    virtual ~IProfileEventCallback() = default;

    virtual void OnSyncCompleted(const SyncResult& syncResults) {}
    virtual void OnProfileChanged(const ProfileChangeNotification& changeNotification) {}
};
}  // namespace DeviceProfile
}  // namespace OHOS
#endif  // OHOS_DEVICE_PROFILE_I_PROFILE_EVENT_CALLBACK_H
