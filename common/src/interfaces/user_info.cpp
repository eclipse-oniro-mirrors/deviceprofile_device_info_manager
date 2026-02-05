/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_info.h"
#include "macro_utils.h"
#include <cstdint>
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "UserInfo";
}
bool UserInfo::Marshalling(MessageParcel& parcel) const
{
    WRITE_HELPER(parcel, String, udid);
    WRITE_HELPER(parcel, Int32, userId);
    WRITE_HELPER(parcel, Int64, serviceId);

    return true;
}
bool UserInfo::UnMarshalling(MessageParcel& parcel)
{
    READ_HELPER_RET(parcel, String, udid, false);
    READ_HELPER_RET(parcel, Int32, userId, false);
    READ_HELPER_RET(parcel, Int64, serviceId, false);

    return true;
}

std::string UserInfo::dump() const
{
    return std::string("userInfo { udid = ") + ProfileUtils::GetAnonyString(udid.c_str()) +
        ", userId = " + std::to_string(userId) + ", serviceId = " + std::to_string(serviceId) + " }";
}
} // namespace DistributedDeviceProfile
} // namespace OHOS