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

#ifndef OHOS_DP_USER_INFO_H
#define OHOS_DP_USER_INFO_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
struct UserInfo : public DpParcel {
    std::string udid = "";
    int32_t userId = DEFAULT_USER_ID;
    int64_t serviceId = DEFAULT_SERVICE_ID;
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;
};
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
#endif //OHOS_DP_USER_INFO_H