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

#ifndef OHOS_DISTRIBUTED_DEVICE_PROFILE_ONLINE_SYNC_TABLE_H
#define OHOS_DISTRIBUTED_DEVICE_PROFILE_ONLINE_SYNC_TABLE_H

#include "device_profile_storage.h"

namespace OHOS {
namespace DeviceProfile {
class OnlineSyncTable : public DeviceProfileStorage {
public:
    OnlineSyncTable();
    ~OnlineSyncTable() = default;

    void Init() override;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DEVICE_PROFILE_ONLINE_SYNC_TABLE_H