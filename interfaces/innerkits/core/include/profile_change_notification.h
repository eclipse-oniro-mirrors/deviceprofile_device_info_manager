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

#ifndef OHOS_DEVICE_PROFILE_CHANGE_NOTIFICATION_H
#define OHOS_DEVICE_PROFILE_CHANGE_NOTIFICATION_H

#include <vector>
#include <map>

#include "parcel.h"

namespace OHOS {
namespace DeviceProfile {
enum class ProfileChangeType : uint8_t {
    UNKNOWN_CHANGE_TYPE = 0,
    INSERTED = 1,
    UPDATED = 2,
    DELETED = 3
};

using Service2Index = std::map<std::string, uint32_t>;

struct ProfileEntry {
    template<typename T>
    ProfileEntry(T&& k, T&& val, ProfileChangeType type)
        : key(std::forward<T>(k)), value(std::forward<T>(val)), changeType(type) {}
    ProfileEntry() {}
    ~ProfileEntry() = default;

    bool Marshalling(Parcel& parcel) const;
    bool Unmarshalling(Parcel& parcel);

    std::string key;
    std::string value;
    ProfileChangeType changeType {ProfileChangeType::UNKNOWN_CHANGE_TYPE};
};

class ProfileChangeNotification : public Parcelable {
public:
    ProfileChangeNotification(std::vector<ProfileEntry>& profileEntries,
        std::string& networkId, bool isLocal)
        : profileEntries_(std::move(profileEntries)),
          deviceId_(std::move(networkId)), isLocal_(isLocal) {}
    ProfileChangeNotification() {}
    ~ProfileChangeNotification() = default;

    const std::vector<ProfileEntry>& GetProfileEntries() const;
    const std::string& GetDeviceId() const;
    bool IsLocal() const;

    bool Marshalling(Parcel& parcel) const override;
    bool Unmarshalling(Parcel& parcel);

private:
    std::vector<ProfileEntry> profileEntries_;
    std::string deviceId_;
    bool isLocal_ {false};
};
}  // namespace DeviceProfile
}  // namespace OHOS
#endif  // OHOS_DEVICE_PROFILE_CHANGE_NOTIFICATION_H
