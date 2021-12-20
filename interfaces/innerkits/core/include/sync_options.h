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

#ifndef OHOS_SYNC_OPERATION_H
#define OHOS_SYNC_OPERATION_H

#include <list>
#include "parcel.h"
#include "types.h"

namespace OHOS {
namespace DeviceProfile {
class SyncOptions : public Parcelable {
public:
    SyncOptions() = default;
    ~SyncOptions() = default;

    const std::list<std::string>& GetDeviceList() const;
    DistributedKv::SyncMode GetSyncMode() const;

    void AddDevice(const std::string& deviceId);
    void SetSyncMode(DistributedKv::SyncMode mode);

    bool Marshalling(Parcel& parcel) const override;
    bool Unmarshalling(Parcel& parcel);

private:
    DistributedKv::SyncMode syncMode_ {DistributedKv::SyncMode::PUSH};
    std::list<std::string> syncDevIds_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif  // OHOS_SYNC_OPERATION_H