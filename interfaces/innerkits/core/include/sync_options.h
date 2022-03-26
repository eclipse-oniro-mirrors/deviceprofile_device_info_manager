/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_PROFILE_SYNC_OPTIONS_H
#define OHOS_DEVICE_PROFILE_SYNC_OPTIONS_H

#include <list>

#include "parcel.h"

namespace OHOS {
namespace DeviceProfile {
// must keep same with DistributedKv::SyncMode
enum class SyncMode : int64_t {
    PULL,
    PUSH,
    PUSH_PULL,
};

class SyncOptions : public Parcelable {
public:
    SyncOptions() = default;
    ~SyncOptions() = default;

    const std::list<std::string>& GetDeviceList() const;
    SyncMode GetSyncMode() const;

    void AddDevice(const std::string& deviceId);
    void SetSyncMode(SyncMode mode);

    bool Marshalling(Parcel& parcel) const override;
    bool Unmarshalling(Parcel& parcel);

private:
    SyncMode syncMode_ {SyncMode::PUSH};
    std::list<std::string> syncDevIds_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif  // OHOS_DEVICE_PROFILE_SYNC_OPTIONS_H