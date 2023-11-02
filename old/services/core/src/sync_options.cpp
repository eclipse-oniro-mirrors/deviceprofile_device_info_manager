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

#include "sync_options.h"

#include <iosfwd>
#include <list>
#include <string>

#include "device_profile_log.h"
#include "parcel.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SyncOptions";
constexpr int32_t MAX_DEVICE_LEN = 1000000;
}

const std::list<std::string>& SyncOptions::GetDeviceList() const
{
    return syncDevIds_;
}

void SyncOptions::AddDevice(const std::string& deviceId)
{
    syncDevIds_.emplace_back(deviceId);
}

SyncMode SyncOptions::GetSyncMode() const
{
    return syncMode_;
}

void SyncOptions::SetSyncMode(SyncMode mode)
{
    syncMode_ = mode;
}

bool SyncOptions::Marshalling(Parcel& parcel) const
{
    PARCEL_WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncMode_), false);
    PARCEL_WRITE_HELPER_RET(parcel, Int32, static_cast<int32_t>(syncDevIds_.size()), false);
    for (const auto& deviceId : syncDevIds_) {
        PARCEL_WRITE_HELPER_RET(parcel, String, deviceId, false);
    }
    return true;
}

bool SyncOptions::Unmarshalling(Parcel& parcel)
{
    int32_t mode = 0;
    PARCEL_READ_HELPER_RET(parcel, Int32, mode, false);
    syncMode_ = static_cast<DeviceProfile::SyncMode>(mode);
    int32_t size = 0;
    PARCEL_READ_HELPER_RET(parcel, Int32, size, false);
    if (size > MAX_DEVICE_LEN) {
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string deviceId;
        PARCEL_READ_HELPER_RET(parcel, String, deviceId, false);
        syncDevIds_.emplace_back(deviceId);
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS