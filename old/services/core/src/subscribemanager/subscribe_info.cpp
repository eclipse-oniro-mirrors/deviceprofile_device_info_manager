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

#include "subscribe_info.h"

#include <initializer_list>
#include <iosfwd>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <type_traits>
#include <vector>

#include "device_profile_log.h"
#include "parcel.h"
#include "parcel_helper.h"
#include "profile_event.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "SubscribeInfo";
}

bool SubscribeInfo::Marshalling(Parcel& parcel) const
{
    PARCEL_WRITE_HELPER_RET(parcel, Uint32, profileEvent, false);
    PARCEL_WRITE_HELPER_RET(parcel, String, extraInfo.dump(), false);
    return true;
}

bool SubscribeInfo::Unmarshalling(Parcel& parcel)
{
    profileEvent = static_cast<ProfileEvent>(parcel.ReadUint32());
    if (profileEvent >= EVENT_PROFILE_END || profileEvent == EVENT_UNKNOWN) {
        HILOGE("invalid profile event, %{public}d", profileEvent);
        return false;
    }
    std::string value = parcel.ReadString();
    extraInfo = ExtraInfo::parse(value, nullptr, false);
    if (extraInfo.is_discarded()) {
        HILOGE("parse extra info failed, %{public}s", value.c_str());
        return false;
    }
    return true;
}

bool SubscribeInfo::operator!=(const SubscribeInfo& rhs) const
{
    return ((profileEvent != rhs.profileEvent) || (extraInfo != rhs.extraInfo));
}
} // namespace DeviceProfile
} // namespace OHOS