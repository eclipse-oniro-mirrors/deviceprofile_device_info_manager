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

#include "profile_change_notification.h"

#include <iosfwd>
#include <string>
#include <type_traits>
#include <vector>

#include "device_profile_log.h"
#include "parcel.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ProfileChangeNotification";
constexpr int32_t MAX_ENTRY_LEN = 1000000;
}

const std::vector<ProfileEntry>& ProfileChangeNotification::GetProfileEntries() const
{
    return profileEntries_;
}

const std::string& ProfileChangeNotification::GetDeviceId() const
{
    return deviceId_;
}

bool ProfileChangeNotification::IsLocal() const
{
    return isLocal_;
}

bool ProfileChangeNotification::Marshalling(Parcel& parcel) const
{
    int32_t entrySize = static_cast<int32_t>(profileEntries_.size());
    PARCEL_WRITE_HELPER_RET(parcel, Int32, entrySize, false);
    for (const auto& profileEntry : profileEntries_) {
        if (!profileEntry.Marshalling(parcel)) {
            return false;
        }
    }
    PARCEL_WRITE_HELPER_RET(parcel, String, deviceId_, false);

    return true;
}

bool ProfileChangeNotification::Unmarshalling(Parcel& parcel)
{
    int32_t entrySize = parcel.ReadInt32();
    if (entrySize < 0 || entrySize > MAX_ENTRY_LEN) {
        HILOGE("invalid entrySize = %{public}d", entrySize);
        return false;
    }
    profileEntries_.reserve(entrySize);
    for (int32_t i = 0; i < entrySize; i++) {
        ProfileEntry profileEntry;
        if (!profileEntry.Unmarshalling(parcel)) {
            return false;
        }
        profileEntries_.emplace_back(std::move(profileEntry));
    }
    PARCEL_READ_HELPER_RET(parcel, String, deviceId_, false);
    return true;
}

bool ProfileEntry::Marshalling(Parcel& parcel) const
{
    PARCEL_WRITE_HELPER_RET(parcel, String, key, false);
    PARCEL_WRITE_HELPER_RET(parcel, String, value, false);
    PARCEL_WRITE_HELPER_RET(parcel, Uint8, static_cast<uint8_t>(changeType), false);
    return true;
}

bool ProfileEntry::Unmarshalling(Parcel& parcel)
{
    PARCEL_READ_HELPER_RET(parcel, String, key, false);
    PARCEL_READ_HELPER_RET(parcel, String, value, false);
    uint8_t type = 0;
    PARCEL_READ_HELPER_RET(parcel, Uint8, type, false);
    changeType = static_cast<ProfileChangeType>(type);
    return true;
}
}  // namespace DeviceProfile
}  // namespace OHOS
