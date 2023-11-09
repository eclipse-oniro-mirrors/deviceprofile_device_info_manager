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

#ifndef OHOS_DP_SYNC_OPTIONS_H
#define OHOS_DP_SYNC_OPTIONS_H

#include <list>
#include <string>
#include <vector>
#include "dp_parcel.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_enums.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SyncOptions : public DpParcel {
public:
    SyncOptions() = default;
    ~SyncOptions() = default;

    std::vector<std::string> GetDeviceList() const;
    SyncMode GetSyncMode() const;

    void AddDevice(const std::string& deviceId);
    void SetSyncMode(SyncMode mode);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    void dump() const override;

private:
    SyncMode syncMode_{SyncMode::PUSH_PULL};
    std::vector<std::string> syncDeviceIds_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif  // OHOS_DP_DEVICE_PROFILE_SYNC_OPTIONS_H